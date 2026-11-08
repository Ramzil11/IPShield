import { execFile } from 'child_process';
import path from 'path';
import { ShieldRule } from '../shared/types';

interface ProcessInfo {
  pid: number;
  ppid: number;
  comm: string;
  args: string;
}

export class ProcessGuard {
  // ruleId -> Set of currently frozen PIDs
  private frozenByRule: Map<string, Set<number>> = new Map();
  private isScanning: boolean = false;

  public async enforce(
    rules: ShieldRule[],
    allowedMap: Record<string, boolean>
  ): Promise<Record<string, number[]>> {
    if (this.isScanning) {
      return this.getFrozenSnapshot();
    }
    this.isScanning = true;

    try {
      const activeRuleMap = new Map(rules.map(r => [r.id, r]));

      // 1. If a rule was deleted, is now allowed, or has no process targets left, unfreeze its PIDs
      for (const [ruleId, pidSet] of this.frozenByRule.entries()) {
        const rule = activeRuleMap.get(ruleId);
        const hasProcessTargets = Boolean(
          rule && (rule.processes.length > 0 || rule.appPaths.length > 0)
        );
        if (!rule || allowedMap[ruleId] || !hasProcessTargets) {
          for (const pid of pidSet) {
            await this.resumeProcess(pid);
          }
          this.frozenByRule.delete(ruleId);
        }
      }

      // 2. For blocked rules, scan running processes and freeze matching process trees
      const blockedRules = rules.filter(
        r => !allowedMap[r.id] && (r.processes.length > 0 || r.appPaths.length > 0)
      );

      if (blockedRules.length > 0) {
        const procList = await this.listProcesses();
        for (const rule of blockedRules) {
          const matchedPids = this.findMatchingPidsForRule(rule, procList);
          const matchedSet = new Set(matchedPids);
          let setForRule = this.frozenByRule.get(rule.id);
          if (!setForRule) {
            setForRule = new Set<number>();
            this.frozenByRule.set(rule.id, setForRule);
          }

          // Resume any PIDs that were previously frozen for this rule but no longer match after rule edit
          for (const frozenPid of Array.from(setForRule)) {
            if (!matchedSet.has(frozenPid)) {
              await this.resumeProcess(frozenPid);
              setForRule.delete(frozenPid);
            }
          }

          for (const pid of matchedPids) {
            if (!setForRule.has(pid)) {
              const ok = await this.suspendProcess(pid);
              if (ok) {
                setForRule.add(pid);
              }
            }
          }
        }
      }
    } catch (err) {
      console.error('[ProcessGuard] Error enforcing process guard:', err);
    } finally {
      this.isScanning = false;
    }

    return this.getFrozenSnapshot();
  }

  public async unfreezeAll(): Promise<void> {
    for (const [, pidSet] of this.frozenByRule.entries()) {
      for (const pid of pidSet) {
        await this.resumeProcess(pid);
      }
    }
    this.frozenByRule.clear();
  }

  private getFrozenSnapshot(): Record<string, number[]> {
    const out: Record<string, number[]> = {};
    for (const [ruleId, pidSet] of this.frozenByRule.entries()) {
      out[ruleId] = Array.from(pidSet);
    }
    return out;
  }

  private findMatchingPidsForRule(rule: ShieldRule, procs: ProcessInfo[]): number[] {
    const selfPid = process.pid;
    const directPids = new Set<number>();

    const lowerAppPaths = rule.appPaths.map(p => p.toLowerCase());
    const lowerProcNames = rule.processes.map(p => p.toLowerCase());

    for (const p of procs) {
      if (p.pid === selfPid) continue;
      const commLower = p.comm.toLowerCase();
      const argsLower = p.args.toLowerCase();

      // Never freeze IPShield itself or its Electron helper processes
      if (
        argsLower.includes('ipshield') ||
        argsLower.includes('ai-trafic-check') ||
        argsLower.includes('electron.app/contents/frameworks/electron helper')
      ) {
        continue;
      }

      let matched = false;

      // Check full app bundle paths (e.g. /Applications/Claude.app)
      for (const appPath of lowerAppPaths) {
        if (appPath && (commLower.includes(appPath) || argsLower.includes(appPath))) {
          matched = true;
          break;
        }
      }

      // Check process names / CLI binaries (case-insensitive)
      if (!matched) {
        const commBase = path.basename(commLower);
        for (const target of lowerProcNames) {
          if (!target) continue;
          if (target.includes('/') || target.includes('\\')) {
            // Package or bundle path like @anthropic-ai/claude-code or /Applications/Claude.app
            if (commLower.includes(target) || argsLower.includes(target)) {
              matched = true;
              break;
            }
          } else {
            if (
              commBase === target ||
              commBase === `${target}.exe` ||
              argsLower.includes(`/${target} `) ||
              argsLower.endsWith(`/${target}`) ||
              argsLower.includes(`\\${target}.exe`)
            ) {
              matched = true;
              break;
            }
          }
        }
      }

      if (matched) {
        directPids.add(p.pid);
      }
    }

    // Expand to child processes (process tree)
    let added = true;
    while (added) {
      added = false;
      for (const p of procs) {
        if (!directPids.has(p.pid) && directPids.has(p.ppid) && p.pid !== selfPid) {
          directPids.add(p.pid);
          added = true;
        }
      }
    }

    return Array.from(directPids);
  }

  private listProcesses(): Promise<ProcessInfo[]> {
    if (process.platform === 'win32') {
      return new Promise(resolve => {
        execFile(
          'powershell.exe',
          [
            '-NoProfile',
            '-Command',
            'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress'
          ],
          { timeout: 3000 },
          (err, stdout) => {
            if (err || !stdout) return resolve([]);
            try {
              const raw = JSON.parse(stdout);
              const arr = Array.isArray(raw) ? raw : [raw];
              resolve(
                arr.map(item => ({
                  pid: Number(item.ProcessId),
                  ppid: Number(item.ParentProcessId),
                  comm: String(item.Name || ''),
                  args: String(item.CommandLine || item.Name || '')
                }))
              );
            } catch {
              resolve([]);
            }
          }
        );
      });
    }

    // macOS / Linux
    return new Promise(resolve => {
      execFile('ps', ['-axo', 'pid=,ppid=,comm=,args='], { timeout: 2000 }, (err, stdout) => {
        if (err || !stdout) return resolve([]);
        const lines = stdout.split('\n');
        const list: ProcessInfo[] = [];
        for (const line of lines) {
          const match = line.trim().match(/^(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/);
          if (match) {
            list.push({
              pid: Number(match[1]),
              ppid: Number(match[2]),
              comm: match[3],
              args: match[4]
            });
          }
        }
        resolve(list);
      });
    });
  }

  private async suspendProcess(pid: number): Promise<boolean> {
    if (process.platform === 'win32') {
      return this.winSuspendResume(pid, true);
    }
    try {
      process.kill(pid, 'SIGSTOP');
      return true;
    } catch {
      return false;
    }
  }

  private async resumeProcess(pid: number): Promise<boolean> {
    if (process.platform === 'win32') {
      return this.winSuspendResume(pid, false);
    }
    try {
      process.kill(pid, 'SIGCONT');
      return true;
    } catch {
      return false;
    }
  }

  private winSuspendResume(pid: number, suspend: boolean): Promise<boolean> {
    const method = suspend ? 'NtSuspendProcess' : 'NtResumeProcess';
    const psScript = `
$code = @"
using System;
using System.Runtime.InteropServices;
public class ProcUtil {
  [DllImport("ntdll.dll")] public static extern int ${method}(IntPtr processHandle);
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
"@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
$h = [ProcUtil]::OpenProcess(0x0800, $false, ${pid})
if ($h -ne [IntPtr]::Zero) {
  [ProcUtil]::${method}($h) | Out-Null
  [ProcUtil]::CloseHandle($h) | Out-Null
}
`;
    return new Promise(resolve => {
      execFile('powershell.exe', ['-NoProfile', '-Command', psScript], { timeout: 2500 }, err => {
        resolve(!err);
      });
    });
  }
}

