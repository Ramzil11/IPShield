import { execFile } from 'child_process';
import https from 'https';
import os from 'os';

export type IpChangeCallback = (ip: string) => void;

export class IpMonitor {
  private currentIp: string = 'Определение...';
  private isChecking: boolean = false;
  private generation: number = 0;
  private lastInterfaceSignature: string = '';
  private pollTimer: NodeJS.Timeout | null = null;
  private ifaceTimer: NodeJS.Timeout | null = null;
  private listeners: IpChangeCallback[] = [];
  private providerIndex: number = 0;

  public onIpChange(cb: IpChangeCallback): void {
    this.listeners.push(cb);
  }

  public getCurrentIp(): string {
    return this.currentIp;
  }

  public isBusy(): boolean {
    return this.isChecking;
  }

  public getGeneration(): number {
    return this.generation;
  }

  /**
   * Simulates or handles an immediate network interface change:
   * increments generation so any in-flight HTTP check is discarded (R-2),
   * sets fail-closed status, and notifies listeners immediately (S-5).
   */
  public handleInterfaceChange(): void {
    this.generation++;
    this.currentIp = 'Смена сети...';
    this.notify();
  }

  public start(intervalMs: number = 2500, ifacePollMs: number = 200): void {
    this.lastInterfaceSignature = this.computeInterfaceSignature();
    void this.checkNow(true, true);

    // Fast 200ms local network interface watcher (catches VPN utun connects / disconnects immediately)
    this.ifaceTimer = setInterval(() => {
      const sig = this.computeInterfaceSignature();
      if (sig !== this.lastInterfaceSignature) {
        this.lastInterfaceSignature = sig;

        // R-2 & S-5: Increment generation to invalidate any in-flight check and fail-closed immediately
        this.handleInterfaceChange();

        // Flush DNS cache only on interface transition (B-8) and verify new public IP
        void this.checkNow(true, true);
        setTimeout(() => {
          void this.checkNow(true, true);
        }, 1200);
      }
    }, ifacePollMs);

    // Periodic public IP verification (without redundant DNS cache flushes on every tick - B-8)
    this.pollTimer = setInterval(() => {
      void this.checkNow(false, false);
    }, intervalMs);
  }

  public stop(): void {
    this.generation++;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    if (this.ifaceTimer) {
      clearInterval(this.ifaceTimer);
      this.ifaceTimer = null;
    }
  }

  public async checkNow(
    forceEvenIfBusy: boolean = false,
    flushDns: boolean = false
  ): Promise<string> {
    if (this.isChecking && !forceEvenIfBusy) {
      return this.currentIp;
    }
    const gen = ++this.generation;
    this.isChecking = true;

    try {
      if (flushDns) {
        await this.flushUserDnsCache();
      }

      if (gen !== this.generation) {
        return this.currentIp;
      }

      const ipv4Parser = (body: string): string | null => {
        const trimmed = body.trim();
        const ipv4Regex =
          /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
        return ipv4Regex.test(trimmed) ? trimmed : null;
      };

      const providers: Array<() => Promise<string | null>> = [
        () =>
          this.fetchHttp('https://www.cloudflare.com/cdn-cgi/trace', body => {
            const match = body.match(
              /^ip=((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/m
            );
            return match ? match[0].replace('ip=', '').trim() : null;
          }),
        () => this.fetchHttp('https://api.ipify.org', ipv4Parser),
        () => this.fetchHttp('https://ipv4.icanhazip.com', ipv4Parser),
        () => this.fetchHttp('https://checkip.amazonaws.com', ipv4Parser)
      ];

      let ip: string | null = null;
      for (let i = 0; i < providers.length; i++) {
        if (gen !== this.generation) {
          return this.currentIp;
        }
        const idx = (this.providerIndex + i) % providers.length;
        ip = await providers[idx]();
        if (ip) {
          this.providerIndex = (idx + 1) % providers.length;
          break;
        }
      }

      // R-2: Discard result if a newer check or interface change occurred while waiting
      if (gen !== this.generation) {
        return this.currentIp;
      }

      const nextIp = ip || 'Нет сети';
      if (nextIp !== this.currentIp) {
        this.currentIp = nextIp;
        this.notify();
      }
    } catch {
      if (gen === this.generation && this.currentIp !== 'Нет сети') {
        this.currentIp = 'Нет сети';
        this.notify();
      }
    } finally {
      if (gen === this.generation) {
        this.isChecking = false;
      }
    }

    return this.currentIp;
  }

  /**
   * Flushes OS user-space DNS cache without requiring sudo privileges.
   */
  private flushUserDnsCache(): Promise<void> {
    return new Promise(resolve => {
      if (process.platform === 'darwin') {
        execFile('/usr/bin/dscacheutil', ['-flushcache'], { timeout: 1000 }, () => resolve());
      } else if (process.platform === 'win32') {
        execFile('ipconfig', ['/flushdns'], { timeout: 1500 }, () => resolve());
      } else {
        resolve();
      }
    });
  }

  private notify(): void {
    for (const cb of this.listeners) {
      try {
        cb(this.currentIp);
      } catch (err) {
        console.error('[IpMonitor] Listener error:', err);
      }
    }
  }

  /**
   * Computes network interface signature using only non-internal IPv4 addresses (B-8)
   * so temporary IPv6 privacy extensions do not trigger false network resets.
   */
  private computeInterfaceSignature(): string {
    const nets = os.networkInterfaces();
    const parts: string[] = [];
    for (const name of Object.keys(nets).sort()) {
      const list = nets[name] || [];
      for (const item of list) {
        if (!item.internal && item.family === 'IPv4') {
          parts.push(`${name}:${item.address}`);
        }
      }
    }
    return parts.join('|');
  }

  /**
   * Unified HTTP request helper with IPv4 family pinning and bounded response size (Q-2, B-4).
   */
  private fetchHttp(
    baseUrl: string,
    parseFn: (text: string) => string | null
  ): Promise<string | null> {
    return new Promise(resolve => {
      let settled = false;
      const done = (val: string | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(hardTimer);
        resolve(val);
      };

      const urlWithBust = `${baseUrl}?_=${Date.now()}`;
      const req = https.get(
        urlWithBust,
        {
          family: 4, // B-4: Force IPv4 resolution to prevent v4/v6 provider flapping
          agent: false,
          timeout: 2000,
          headers: {
            Connection: 'close',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            Pragma: 'no-cache',
            'User-Agent': 'IPShield/1.0'
          }
        },
        res => {
          let body = '';
          const maxBytes = 8192; // Prevent excessive data allocation
          res.on('data', chunk => {
            body += chunk;
            if (body.length > maxBytes) {
              res.destroy();
              done(null);
            }
          });
          res.on('end', () => {
            res.destroy();
            done(parseFn(body));
          });
          res.on('error', () => done(null));
        }
      );

      const hardTimer = setTimeout(() => {
        try {
          req.destroy();
        } catch {
          // ignore
        }
        done(null);
      }, 2200);

      req.on('error', () => done(null));
      req.on('timeout', () => {
        try {
          req.destroy();
        } catch {
          // ignore
        }
        done(null);
      });
    });
  }
}
