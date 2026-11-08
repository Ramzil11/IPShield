import https from 'https';
import os from 'os';

export type IpChangeCallback = (ip: string) => void;

export class IpMonitor {
  private currentIp: string = 'Определение...';
  private isChecking: boolean = false;
  private lastInterfaceSignature: string = '';
  private pollTimer: NodeJS.Timeout | null = null;
  private ifaceTimer: NodeJS.Timeout | null = null;
  private listeners: IpChangeCallback[] = [];

  public onIpChange(cb: IpChangeCallback): void {
    this.listeners.push(cb);
  }

  public getCurrentIp(): string {
    return this.currentIp;
  }

  public isBusy(): boolean {
    return this.isChecking;
  }

  public start(intervalMs: number = 3500): void {
    this.lastInterfaceSignature = this.computeInterfaceSignature();
    void this.checkNow();

    // Fast 1s local network interface watcher (catches VPN connect/disconnect immediately)
    this.ifaceTimer = setInterval(() => {
      const sig = this.computeInterfaceSignature();
      if (sig !== this.lastInterfaceSignature) {
        this.lastInterfaceSignature = sig;
        void this.checkNow();
      }
    }, 1000);

    // Periodic public IP verification
    this.pollTimer = setInterval(() => {
      void this.checkNow();
    }, intervalMs);
  }

  public stop(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.ifaceTimer) clearInterval(this.ifaceTimer);
  }

  public async checkNow(): Promise<string> {
    if (this.isChecking) return this.currentIp;
    this.isChecking = true;

    try {
      const ip =
        (await this.fetchCloudflareTrace()) ||
        (await this.fetchPlainTextIp('https://api.ipify.org')) ||
        (await this.fetchPlainTextIp('https://icanhazip.com'));

      const nextIp = ip || 'Нет сети';
      if (nextIp !== this.currentIp) {
        this.currentIp = nextIp;
        this.notify();
      }
    } catch {
      if (this.currentIp !== 'Нет сети') {
        this.currentIp = 'Нет сети';
        this.notify();
      }
    } finally {
      this.isChecking = false;
    }

    return this.currentIp;
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

  private fetchCloudflareTrace(): Promise<string | null> {
    return new Promise(resolve => {
      const req = https.get(
        'https://1.1.1.1/cdn-cgi/trace',
        { timeout: 2500 },
        res => {
          let body = '';
          res.on('data', chunk => (body += chunk));
          res.on('end', () => {
            const match = body.match(/^ip=([0-9a-fA-F.:]+)$/m);
            resolve(match ? match[1].trim() : null);
          });
        }
      );
      req.on('error', () => resolve(null));
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });
    });
  }

  private fetchPlainTextIp(url: string): Promise<string | null> {
    return new Promise(resolve => {
      const req = https.get(url, { timeout: 2500 }, res => {
        let body = '';
        res.on('data', chunk => (body += chunk));
        res.on('end', () => {
          const trimmed = body.trim();
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
            resolve(trimmed);
          } else {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });
    });
  }
}

