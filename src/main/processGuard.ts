import { execFile } from 'child_process';
import fs from 'fs';
import path from 'path';
import { app } from 'electron';
import { ShieldRule } from '../shared/types';
import { isDeniedSystemProcess } from '../shared/validation';

export interface ProcessInfo {
  pid: number;
  ppid: number;
  comm: string;
  args: string;
}

export interface FrozenProcessRecord {
  pid: number;
  comm: string;
  suspendedAt: number;
}

export class ProcessGuard {
  // ruleId -> Set of currently frozen PIDs
  private frozenByRule: Map<string, Set<number>> = new Map();
  // PID -> comm name for tracking and crash recovery
  private frozenPidDetails: Map<number, string> = new Map();
  private ignoredPids: Set<number> = new Set([process.pid]);
  private enforceChain: Promise<Record<string, number[]>> = Promise.resolve({});
  private lastError: string | null = null;
  private recoveryFilePath: string;
  private customProcessLister?: () => Promise<ProcessInfo[]>;

  constructor(options?: {
    recoveryFilePath?: string;
    customProcessLister?: () => Promise<ProcessInfo[]>;
  }) {
    if (options?.recoveryFilePath) {
      this.recoveryFilePath = options.recoveryFilePath;
    } else {
      // B-3: Use app.getPath('userData') instead of process.cwd() (which is '/' when launched from Finder)
      const userDataPath =
        app && typeof app.getPath === 'function'
          ? app.getPath('userData')
          : path.join(__dirname, '../../.data');
      if (!fs.existsSync(userDataPath)) {
        try {
          fs.mkdirSync(userDataPath, { recursive: true });
        } catch {
          // ignore
        }
      }
      this.recoveryFilePath = path.join(userDataPath, 'frozen-recovery.json');
    }

    if (options?.customProcessLister) {
      this.customProcessLister = options.customProcessLister;
    }

    // Run startup crash recovery synchronously for immediate file cleanup and chain async resume
    this.restoreFrozenProcessesOnStartup();
  }

  public getRecoveryFilePath(): string {
    return this.recoveryFilePath;
  }

  public setIgnoredPids(pids: number[]): void {
    this.ignoredPids = new Set([process.pid, ...pids]);
  }

  public addIgnoredPid(pid: number): void {
    this.ignoredPids.add(pid);
  }

  public getLastError(): string | null {
    return this.lastError;
  }

  /**
   * Serializes enforcement calls sequentially via promise chaining (B-1).
   * Prevents race conditions between concurrent IP checks, timer triggers, and UI saves.
   */
  public enforce(
    rules: ShieldRule[],
    allowedMap: Record<string, boolean>
  ): Promise<Record<string, number[]>> {
    this.enforceChain = this.enforceChain
      .catch(() => ({}))
      .then(() => this.runSerializedEnforce(rules, allowedMap));
    return this.enforceChain;
  }

  private async runSerializedEnforce(
    rules: ShieldRule[],
    allowedMap: Record<string, boolean>
  ): Promise<Record<string, number[]>> {
    // 1. Unfreeze rules that are newly allowed or have no targets
    const activeRuleMap = new Map(rules.map(r => [r.id, r]));
    const pidsToResume: number[] = [];

    for (const [ruleId, pidSet] of this.frozenByRule.entries()) {
      const rule = activeRuleMap.get(ruleId);
      const hasProcessTargets = Boolean(
        rule && (rule.processes.length > 0 || rule.appPaths.length > 0)
      );

      if (!rule || allowedMap[ruleId] || !hasProcessTargets) {
        for (const pid of pidSet) {
          pidsToResume.push(pid);
          this.frozenPidDetails.delete(pid);
        }
        this.frozenByRule.delete(ruleId);
      }
    }

    if (pidsToResume.length > 0) {
      await this.resumeProcessesBatch(pidsToResume);
    }

    // 2. Scan and enforce blocked rules
    const blockedRules = rules.filter(
      r => !allowedMap[r.id] && (r.processes.length > 0 || r.appPaths.length > 0)
    );

    if (blockedRules.length > 0) {
      const procList = await this.listProcesses();

      if (procList.length > 0) {
        this.lastError = null;
        for (const rule of blockedRules) {
          const matchedPids = this.findMatchingPidsForRule(rule, procList);
          const matchedSet = new Set(matchedPids);

          let setForRule = this.frozenByRule.get(rule.id);
          if (!setForRule) {
            setForRule = new Set<number>();
            this.frozenByRule.set(rule.id, setForRule);
          }

          // Resume any PIDs that were previously frozen for this rule but no longer match
          const ruleResumePids: number[] = [];
          for (const frozenPid of Array.from(setForRule)) {
            if (!matchedSet.has(frozenPid)) {
              ruleResumePids.push(frozenPid);
              setForRule.delete(frozenPid);
              this.frozenPidDetails.delete(frozenPid);
            }
          }
          if (ruleResumePids.length > 0) {
            await this.resumeProcessesBatch(ruleResumePids);
          }

          // Suspend newly matched PIDs
          const ruleSuspendPids: number[] = [];
          for (const pid of matchedPids) {
            if (!setForRule.has(pid)) {
              ruleSuspendPids.push(pid);
            }
          }

          if (ruleSuspendPids.length > 0) {
            const suspendedOk = await this.suspendProcessesBatch(ruleSuspendPids);
            if (suspendedOk) {
              for (const pid of ruleSuspendPids) {
                const procInfo = procList.find(p => p.pid === pid);
                const comm = procInfo ? procInfo.comm : 'unknown';
                setForRule.add(pid);
                this.frozenPidDetails.set(pid, comm);
              }
            }
          }
        }
      }
    }

    this.persistRecoveryState();
    return this.getFrozenSnapshot();
  }

  /**
   * Unfreezes all suspended processes, serialized through enforceChain (B-1)
   * so an in-flight scan can never freeze processes after unfreezeAll completes.
   */
  public async unfreezeAll(): Promise<void> {
    this.enforceChain = this.enforceChain
      .catch(() => ({}))
      .then(async () => {
        const allPids: number[] = [];
        for (const [, pidSet] of this.frozenByRule.entries()) {
          for (const pid of pidSet) {
            allPids.push(pid);
            this.frozenPidDetails.delete(pid);
          }
        }
        if (allPids.length > 0) {
          await this.resumeProcessesBatch(allPids);
        }
        this.frozenByRule.clear();
        this.clearRecoveryState();
        return {};
      });
    await this.enforceChain;
  }

  public getFrozenSnapshot(): Record<string, number[]> {
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
    const lowerProcNames = rule.processes
      .filter(p => !isDeniedSystemProcess(p))
      .map(p => p.toLowerCase());

    for (const p of procs) {
      // Exclude self and any explicitly registered helper/app PIDs (S-5)
      if (p.pid === selfPid || this.ignoredPids.has(p.pid)) {
        continue;
      }

      // Deny list: never freeze system processes even when comm is a full path or login shell (B-9, R-3)
      if (isDeniedSystemProcess(p.comm)) {
        continue;
      }

      const commLower = p.comm.toLowerCase();
      const argsLower = p.args.toLowerCase();

      let matched = false;

      // Check full app bundle paths
      for (const appPath of lowerAppPaths) {
        if (appPath && (commLower.includes(appPath) || argsLower.includes(appPath))) {
          matched = true;
          break;
        }
      }

      // Check process names / CLI binaries (case-insensitive)
      if (!matched) {
        const commBase = (commLower.split(/[/\\]/).pop() || commLower).replace(/^-+/, '');
        for (const target of lowerProcNames) {
          if (!target) continue;
          if (target.includes('/') || target.includes('\\')) {
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
              argsLower.includes(` ${target}`) ||
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

    // Expand to child processes (process tree), never pulling in ignored or system PIDs
    let added = true;
    while (added) {
      added = false;
      for (const p of procs) {
        if (
          !directPids.has(p.pid) &&
          directPids.has(p.ppid) &&
          p.pid !== selfPid &&
          !this.ignoredPids.has(p.pid) &&
          !isDeniedSystemProcess(p.comm)
        ) {
          directPids.add(p.pid);
          added = true;
        }
      }
    }

    return Array.from(directPids);
  }

  private listProcesses(): Promise<ProcessInfo[]> {
    if (this.customProcessLister) {
      return this.customProcessLister().catch(err => {
        this.lastError = `Ошибка кастомного сканера процессов: ${err?.message || err}`;
        return [];
      });
    }

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
            if (err || !stdout) {
              this.lastError = 'Сбой получения списка процессов через PowerShell';
              return resolve([]);
            }
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
              this.lastError = 'Ошибка парсинга списка процессов Windows';
              resolve([]);
            }
          }
        );
      });
    }

    // macOS / Linux
    return new Promise(resolve => {
      execFile('ps', ['-axo', 'pid=,ppid=,comm=,args='], { timeout: 2000 }, (err, stdout) => {
        if (err || !stdout) {
          this.lastError = 'Сбой получения списка процессов: ps недоступен';
          return resolve([]);
        }
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

  /**
   * Suspends a batch of PIDs (single PowerShell invocation on Windows for B-7).
   */
  private async suspendProcessesBatch(pids: number[]): Promise<boolean> {
    if (pids.length === 0) return true;
    if (process.platform === 'win32') {
      return this.winSuspendResumeBatch(pids, true);
    }
    let anySuccess = false;
    for (const pid of pids) {
      try {
        process.kill(pid, 'SIGSTOP');
        anySuccess = true;
      } catch {
        // ignore if process exited
      }
    }
    return anySuccess;
  }

  /**
   * Resumes a batch of PIDs (single PowerShell invocation on Windows for B-7).
   */
  private async resumeProcessesBatch(pids: number[]): Promise<boolean> {
    if (pids.length === 0) return true;
    if (process.platform === 'win32') {
      return this.winSuspendResumeBatch(pids, false);
    }
    let anySuccess = false;
    for (const pid of pids) {
      try {
        process.kill(pid, 'SIGCONT');
        anySuccess = true;
      } catch {
        // ignore if process exited
      }
    }
    return anySuccess;
  }

  private winSuspendResumeBatch(pids: number[], suspend: boolean): Promise<boolean> {
    const safePids = pids.filter(p => Number.isInteger(p) && p > 0);
    if (safePids.length === 0) return Promise.resolve(true);

    const method = suspend ? 'NtSuspendProcess' : 'NtResumeProcess';
    const pidArrayLiteral = safePids.join(',');
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
foreach ($p in @(${pidArrayLiteral})) {
  $h = [ProcUtil]::OpenProcess(0x0800, $false, $p)
  if ($h -ne [IntPtr]::Zero) {
    [ProcUtil]::${method}($h) | Out-Null
    [ProcUtil]::CloseHandle($h) | Out-Null
  }
}
`;
    return new Promise(resolve => {
      execFile('powershell.exe', ['-NoProfile', '-Command', psScript], { timeout: 3500 }, err => {
        resolve(!err);
      });
    });
  }

  /**
   * Persists currently suspended processes to disk for crash recovery (B-3).
   */
  private persistRecoveryState(): void {
    try {
      const records: FrozenProcessRecord[] = [];
      for (const [pid, comm] of this.frozenPidDetails.entries()) {
        records.push({
          pid,
          comm,
          suspendedAt: Date.now()
        });
      }
      if (records.length === 0) {
        this.clearRecoveryState();
        return;
      }
      const dir = path.dirname(this.recoveryFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.recoveryFilePath, JSON.stringify(records, null, 2), 'utf-8');
    } catch (err) {
      console.error('[ProcessGuard] Error saving recovery state:', err);
    }
  }

  private clearRecoveryState(): void {
    try {
      if (fs.existsSync(this.recoveryFilePath)) {
        fs.unlinkSync(this.recoveryFilePath);
      }
    } catch {
      // ignore
    }
  }

  /**
   * Checks if any processes were left frozen after a previous crash or kill -9,
   * verifies `comm` when available to prevent signaling reused PIDs, and unfreezes them (B-3).
   */
  private restoreFrozenProcessesOnStartup(): void {
    try {
      if (!fs.existsSync(this.recoveryFilePath)) return;
      const raw = fs.readFileSync(this.recoveryFilePath, 'utf-8');
      const records = JSON.parse(raw) as FrozenProcessRecord[];
      this.clearRecoveryState();

      if (!Array.isArray(records) || records.length === 0) return;

      this.enforceChain = this.enforceChain
        .catch(() => ({}))
        .then(async () => {
          const procList = await this.listProcesses();
          const pidsToResume: number[] = [];

          for (const item of records) {
            if (!item || typeof item.pid !== 'number' || item.pid <= 0) continue;

            if (procList.length > 0) {
              const found = procList.find(p => p.pid === item.pid);
              if (!found) continue;
              const recordedBase = (item.comm || '').split(/[/\\]/).pop()?.toLowerCase();
              const currentBase = (found.comm || '').split(/[/\\]/).pop()?.toLowerCase();
              if (
                !recordedBase ||
                recordedBase === 'unknown' ||
                recordedBase === currentBase
              ) {
                pidsToResume.push(item.pid);
              }
            } else {
              // Fallback when process list cannot be queried (e.g. sandboxed test environment)
              pidsToResume.push(item.pid);
            }
          }

          if (pidsToResume.length > 0) {
            await this.resumeProcessesBatch(pidsToResume);
          }
          return {};
        });
    } catch (err) {
      console.error('[ProcessGuard] Error restoring frozen processes on startup:', err);
    }
  }
}
