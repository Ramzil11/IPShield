import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFile } from 'child_process';
import { app } from 'electron';
import { ShieldRule } from '../shared/types';
import { normalizeAndValidateDomain } from '../shared/validation';

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
   * Grants one-time write access to /etc/hosts for the current user ACL.
   * Never uses chmod 666 fallback to preserve privilege separation.
   */
  public async requestOneTimeElevation(): Promise<boolean> {
    if (this.canWriteHostsDirectly()) {
      this.elevatedReady = true;
      this.lastError = null;
      return true;
    }

    const hostsPath = this.getHostsPath();
    const username = os.userInfo().username;

    // Strict validation of username to avoid shell injection
    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      this.lastError = 'Недопустимое имя пользователя операционной системы';
      return false;
    }

    if (process.platform === 'darwin') {
      const aclEntry = `user:${username} allow write,append`;
      const escapedAcl = aclEntry.replace(/["\\]/g, '\\$&');
      const escapedPath = hostsPath.replace(/["\\]/g, '\\$&');
      const appleScript = `do shell script "/bin/chmod +a " & quoted form of "${escapedAcl}" & " " & quoted form of "${escapedPath}" with administrator privileges`;

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
      const psCmd = `Start-Process icacls -ArgumentList ('"' + '${hostsPath.replace(/'/g, "''")}' + '"', '/grant', '"' + '${username.replace(/'/g, "''")}' + ':(M)"') -Verb RunAs -WindowStyle Hidden -Wait`;
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

  /**
   * Revokes the user ACL / write permission to /etc/hosts.
   */
  public async revokeElevation(): Promise<boolean> {
    const hostsPath = this.getHostsPath();
    const username = os.userInfo().username;

    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      return false;
    }

    // Always clear hosts rules first
    await this.clearAllBlocks();

    if (process.platform === 'darwin') {
      const aclEntry = `user:${username} allow write,append`;
      const escapedAcl = aclEntry.replace(/["\\]/g, '\\$&');
      const escapedPath = hostsPath.replace(/["\\]/g, '\\$&');
      const appleScript = `do shell script "/bin/chmod -a " & quoted form of "${escapedAcl}" & " " & quoted form of "${escapedPath}" with administrator privileges`;

      return new Promise(resolve => {
        execFile('osascript', ['-e', appleScript], err => {
          this.elevatedReady = this.canWriteHostsDirectly();
          this.lastSignature = '__FORCE__';
          resolve(!err);
        });
      });
    } else if (process.platform === 'win32') {
      const psCmd = `Start-Process icacls -ArgumentList ('"' + '${hostsPath.replace(/'/g, "''")}' + '"', '/remove:g', '"' + '${username.replace(/'/g, "''")}' + '"') -Verb RunAs -WindowStyle Hidden -Wait`;
      return new Promise(resolve => {
        execFile('powershell.exe', ['-NoProfile', '-Command', psCmd], err => {
          this.elevatedReady = this.canWriteHostsDirectly();
          this.lastSignature = '__FORCE__';
          resolve(!err);
        });
      });
    }

    return true;
  }

  public async syncDomains(
    rules: ShieldRule[],
    allowedMap: Record<string, boolean>
  ): Promise<void> {
    const blockedDomainsSet = new Set<string>();

    for (const rule of rules) {
      if (!allowedMap[rule.id]) {
        for (const rawDomain of rule.domains) {
          const clean = normalizeAndValidateDomain(rawDomain);
          if (!clean) continue;

          // Strict validation to prevent line injection into hosts (S-2)
          if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(clean)) {
            continue;
          }

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

      this.writeHostsSafely(hostsPath, nextContent, cleaned.trimEnd() + '\n');
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
      this.writeHostsSafely(hostsPath, cleaned, cleaned);
      await this.flushSystemDns();
    } catch {
      // ignore on exit
    }
  }

  private getBackupHostsPath(): string {
    if (this.customHostsPath) {
      return `${this.customHostsPath}.backup`;
    }
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
    return path.join(userDataPath, 'hosts.backup');
  }

  /**
   * Saves a backup of clean hosts in userData before writing in-place to preserve
   * /etc/hosts root:wheel ownership and ACL, then verifies the written content (B-6).
   */
  private writeHostsSafely(hostsPath: string, nextContent: string, cleanContent: string): void {
    const backupPath = this.getBackupHostsPath();
    try {
      if (cleanContent.trim().length > 0) {
        fs.writeFileSync(backupPath, cleanContent, 'utf-8');
      }
    } catch {
      // ignore backup write error
    }

    fs.writeFileSync(hostsPath, nextContent, 'utf-8');

    // Verify integrity after write; restore from backup if file was truncated
    const verified = fs.readFileSync(hostsPath, 'utf-8');
    if (verified.length === 0 && cleanContent.length > 0) {
      fs.writeFileSync(hostsPath, cleanContent, 'utf-8');
      throw new Error('Сбой проверки целостности hosts после записи; восстановлена резервная копия');
    }
  }

  private stripIpShieldBlock(content: string): string {
    const blockRegex = /\r?\n?# >>> IPSHIELD START >>>[\s\S]*?# <<< IPSHIELD END <<<\r?\n?/g;
    return content.replace(blockRegex, '\n');
  }

  private flushSystemDns(): Promise<void> {
    if (this.skipDnsFlush) return Promise.resolve();
    if (process.platform === 'darwin') {
      return new Promise(resolve => {
        execFile('/usr/bin/dscacheutil', ['-flushcache'], { timeout: 1000 }, () => {
          resolve();
        });
      });
    } else if (process.platform === 'win32') {
      return new Promise(resolve => {
        execFile('ipconfig', ['/flushdns'], { timeout: 1500 }, () => resolve());
      });
    }
    return Promise.resolve();
  }
}

