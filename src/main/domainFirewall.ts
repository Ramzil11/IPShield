import fs from 'fs';
import os from 'os';
import { execFile } from 'child_process';
import { ShieldRule } from '../shared/types';

const BLOCK_START = '# >>> IPSHIELD START >>>';
const BLOCK_END = '# <<< IPSHIELD END <<<';

export class DomainFirewall {
  private lastSignature: string = '__INIT__';
  private elevatedReady: boolean = false;
  private lastError: string | null = null;
  private isApplying: boolean = false;
  private customHostsPath?: string;
  private skipDnsFlush: boolean = false;

  constructor(customHostsPath?: string, skipDnsFlush: boolean = false) {
    this.customHostsPath = customHostsPath;
    this.skipDnsFlush = skipDnsFlush;
  }

  public isElevated(): boolean {
    return this.elevatedReady || this.canWriteHostsDirectly();
  }

  public getLastError(): string | null {
    return this.lastError;
  }

  private getHostsPath(): string {
    if (this.customHostsPath) {
      return this.customHostsPath;
    }
    if (process.platform === 'win32') {
      const sysRoot = process.env.SystemRoot || 'C:\\Windows';
      return `${sysRoot}\\System32\\drivers\\etc\\hosts`;
    }
    return '/etc/hosts';
  }

  private canWriteHostsDirectly(): boolean {
    try {
      fs.accessSync(this.getHostsPath(), fs.constants.R_OK | fs.constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Grants one-time write access to /etc/hosts for the current user so future
   * VPN/IP transitions happen in <5ms without repeated password prompts.
   */
  public async requestOneTimeElevation(): Promise<boolean> {
    if (this.canWriteHostsDirectly()) {
      this.elevatedReady = true;
      this.lastError = null;
      return true;
    }

    const hostsPath = this.getHostsPath();
    const username = os.userInfo().username;

    if (process.platform === 'darwin') {
      const cmd = `/bin/chmod +a "user:${username} allow write,append" "${hostsPath}" || /bin/chmod 666 "${hostsPath}"`;
      const appleScript = `do shell script "${cmd.replace(/"/g, '\\"')}" with administrator privileges`;

      return new Promise(resolve => {
        execFile('osascript', ['-e', appleScript], err => {
          if (err) {
            this.lastError = 'Не выданы права на настройку сетевого фильтра';
            resolve(false);
          } else {
            this.elevatedReady = this.canWriteHostsDirectly();
            this.lastError = null;
            this.lastSignature = '__FORCE__';
            resolve(true);
          }
        });
      });
    } else if (process.platform === 'win32') {
      const psCmd = `Start-Process icacls -ArgumentList '"${hostsPath}" /grant "${username}:(M)"' -Verb RunAs -WindowStyle Hidden -Wait`;
      return new Promise(resolve => {
        execFile('powershell.exe', ['-NoProfile', '-Command', psCmd], err => {
          if (err) {
            this.lastError = 'Не выданы права администратора';
            resolve(false);
          } else {
            this.elevatedReady = this.canWriteHostsDirectly();
            this.lastError = null;
            this.lastSignature = '__FORCE__';
            resolve(true);
          }
        });
      });
    }

    return false;
  }

  public async syncDomains(
    rules: ShieldRule[],
    allowedMap: Record<string, boolean>
  ): Promise<void> {
    const blockedDomainsSet = new Set<string>();

    for (const rule of rules) {
      if (!allowedMap[rule.id]) {
        for (const rawDomain of rule.domains) {
          const clean = rawDomain
            .trim()
            .toLowerCase()
            .replace(/^https?:\/\//, '')
            .replace(/\/.*$/, '');
          if (!clean) continue;
          blockedDomainsSet.add(clean);
          if (!clean.startsWith('www.') && clean.split('.').length === 2) {
            blockedDomainsSet.add(`www.${clean}`);
          }
        }
      }
    }

    const sortedDomains = Array.from(blockedDomainsSet).sort();
    const signature = sortedDomains.join(',');

    if (signature === this.lastSignature || this.isApplying) {
      return;
    }

    if (!this.canWriteHostsDirectly()) {
      // If there are domains to block and we don't have write access yet, mark state
      if (sortedDomains.length > 0) {
        this.lastError = 'Требуется однократное разрешение для блокировки доменов в браузере';
      }
      return;
    }

    this.isApplying = true;
    try {
      const hostsPath = this.getHostsPath();
      const rawHosts = fs.readFileSync(hostsPath, 'utf-8');
      const cleaned = this.stripIpShieldBlock(rawHosts);

      let nextContent = cleaned.trimEnd() + '\n';
      if (sortedDomains.length > 0) {
        const lines: string[] = [BLOCK_START];
        for (const d of sortedDomains) {
          lines.push(`0.0.0.0 ${d}`);
          lines.push(`:: ${d}`);
        }
        lines.push(BLOCK_END);
        nextContent += '\n' + lines.join('\n') + '\n';
      }

      fs.writeFileSync(hostsPath, nextContent, 'utf-8');
      this.lastSignature = signature;
      this.elevatedReady = true;
      this.lastError = null;
      await this.flushSystemDns();
    } catch (err: any) {
      this.lastError = err?.message || 'Ошибка записи сетевых правил';
    } finally {
      this.isApplying = false;
    }
  }

  public async clearAllBlocks(): Promise<void> {
    if (!this.canWriteHostsDirectly()) return;
    try {
      const hostsPath = this.getHostsPath();
      const rawHosts = fs.readFileSync(hostsPath, 'utf-8');
      const cleaned = this.stripIpShieldBlock(rawHosts).trimEnd() + '\n';
      fs.writeFileSync(hostsPath, cleaned, 'utf-8');
      await this.flushSystemDns();
    } catch {
      // ignore on exit
    }
  }

  private stripIpShieldBlock(content: string): string {
    const startIdx = content.indexOf(BLOCK_START);
    const endIdx = content.indexOf(BLOCK_END);
    if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
      return (
        content.slice(0, startIdx).trimEnd() +
        '\n' +
        content.slice(endIdx + BLOCK_END.length).trimStart()
      );
    }
    return content;
  }

  private flushSystemDns(): Promise<void> {
    if (this.skipDnsFlush) return Promise.resolve();
    if (process.platform === 'darwin') {
      return new Promise(resolve => {
        execFile('dscacheutil', ['-flushcache'], () => {
          execFile('killall', ['-HUP', 'mDNSResponder'], () => resolve());
        });
      });
    } else if (process.platform === 'win32') {
      return new Promise(resolve => {
        execFile('ipconfig', ['/flushdns'], () => resolve());
      });
    }
    return Promise.resolve();
  }
}

