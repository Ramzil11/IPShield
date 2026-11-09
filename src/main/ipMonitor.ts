import { execFile } from 'child_process';
import https from 'https';
import os from 'os';

export type IpChangeCallback = (ip: string) => void;

function getElectronNet(): {
  net: typeof import('electron').net;
  session: typeof import('electron').session;
} | null {
  if (!process.versions || !process.versions.electron) {
    return null;
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const el = require('electron');
    if (el && typeof el === 'object' && el.net && el.session && el.app?.isReady?.()) {
      return { net: el.net, session: el.session };
    }
  } catch {
    // ignore outside Electron runtime (e.g., Vitest)
  }
  return null;
}

interface ProbeOutcome {
  ip: string | null;
  isFakeIpRoute: boolean;
}

export class IpMonitor {
  private currentIp: string = 'Определение...';
  private directIp: string | null = null;
  private isChecking: boolean = false;
  private generation: number = 0;
  private lastInterfaceSignature: string = '';
  private pollTimer: NodeJS.Timeout | null = null;
  private ifaceTimer: NodeJS.Timeout | null = null;
  private transitionTimers: NodeJS.Timeout[] = [];
  private listeners: IpChangeCallback[] = [];
  private getAllowedIps?: () => string[];

  constructor(getAllowedIps?: () => string[]) {
    this.getAllowedIps = getAllowedIps;
  }

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

    // Fast 200ms local network interface watcher (catches VPN utun / Wintun connects & disconnects immediately)
    this.ifaceTimer = setInterval(() => {
      const sig = this.computeInterfaceSignature();
      if (sig !== this.lastInterfaceSignature) {
        this.lastInterfaceSignature = sig;

        // R-2 & S-5: Increment generation to invalidate any in-flight check and fail-closed immediately
        this.handleInterfaceChange();

        // Clear any previous staggered transition timers
        for (const t of this.transitionTimers) {
          clearTimeout(t);
        }
        this.transitionTimers = [];

        // Flush DNS cache across the entire Wintun / utun initialization window (0ms, 1.2s, 2.8s, 5.0s)
        // On Windows, Wintun + Xray/Sing-box can take 2-4s after adapter creation before FakeIP DNS is ready.
        void this.checkNow(true, true);
        for (const delay of [1200, 2800, 5000]) {
          const timer = setTimeout(() => {
            void this.checkNow(true, true);
          }, delay);
          this.transitionTimers.push(timer);
        }
      }
    }, ifacePollMs);

    // Periodic public IP verification
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
    for (const t of this.transitionTimers) {
      clearTimeout(t);
    }
    this.transitionTimers = [];
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
        const trimmed = body.trim().replace(/^["']+|["']+$/g, '');
        const ipv4Regex =
          /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
        return ipv4Regex.test(trimmed) ? trimmed : null;
      };

      const cloudflareParser = (body: string): string | null => {
        const match = body.match(
          /^ip=((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/m
        );
        return match ? match[0].replace('ip=', '').trim() : null;
      };

      // Query all providers in PARALLEL instead of round-robin rotation.
      // Includes Yandex Internetometer (internet.yandex.net) for RF censorship / TSPU resilience.
      const [cfElectronIp, cfNode, ipify, icanhazip, aws, yandex] = await Promise.all([
        this.fetchViaElectronNet('https://www.cloudflare.com/cdn-cgi/trace', cloudflareParser),
        this.fetchHttp('https://www.cloudflare.com/cdn-cgi/trace', cloudflareParser),
        this.fetchHttp('https://api.ipify.org', ipv4Parser),
        this.fetchHttp('https://ipv4.icanhazip.com', ipv4Parser),
        this.fetchHttp('https://checkip.amazonaws.com', ipv4Parser),
        this.fetchHttp('https://internet.yandex.net/internet/api/v0/ip', ipv4Parser)
      ]);

      // R-2: Discard result if a newer check or interface change occurred while waiting
      if (gen !== this.generation) {
        return this.currentIp;
      }

      const ip = await this.selectEffectiveIp({
        cfElectron: { ip: cfElectronIp, isFakeIpRoute: false },
        cfNode,
        ipify,
        icanhazip,
        aws,
        yandex
      });

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
   * Resolves the effective active public IP from parallel provider results.
   * - When all providers agree (1 unique IP), returns it directly (and records it as directIp if no tunnel is active).
   * - When providers return 2 distinct IPs simultaneously (e.g., Home IP on direct/RU route + VPN IP on tunnel/proxy route),
   *   flushes stale OS DNS cache in the background and deterministically selects the non-direct (VPN) IP.
   */
  public async selectEffectiveIp(results: {
    cfElectron: ProbeOutcome;
    cfNode: ProbeOutcome;
    ipify: ProbeOutcome;
    icanhazip: ProbeOutcome;
    aws: ProbeOutcome;
    yandex?: ProbeOutcome;
  }): Promise<string | null> {
    const yandexOutcome = results.yandex || { ip: null, isFakeIpRoute: false };
    const outcomes = [
      results.cfElectron,
      results.cfNode,
      results.ipify,
      results.icanhazip,
      results.aws,
      yandexOutcome
    ].filter((item): item is { ip: string; isFakeIpRoute: boolean } => Boolean(item.ip));

    if (outcomes.length === 0) {
      return null;
    }

    const orderedIps = outcomes.map(o => o.ip);
    const uniqueIps = Array.from(new Set(orderedIps));

    // 1. Unanimous agreement across all responding providers (including when only Yandex responds under RF TSPU blocks)
    if (uniqueIps.length === 1) {
      const unanimousIp = uniqueIps[0];
      if (!this.hasActiveTunnelInterface() && !outcomes.some(o => o.isFakeIpRoute)) {
        this.directIp = unanimousIp;
      }
      return unanimousIp;
    }

    // Multiple distinct public IPs detected simultaneously!
    // This happens on Windows when Happ routes some endpoints (or System Proxy) through the VPN
    // while other endpoints (or RU/Yandex split-tunnel rules) bypass the tunnel.
    void this.flushUserDnsCache();

    // 2. Signal A: Any socket connected to a FakeIP (198.18.0.0/15) is 100% routed via Happ TUN!
    const fakeIpOutcome = outcomes.find(o => o.isFakeIpRoute);
    if (fakeIpOutcome) {
      const nonFakeOutcome = outcomes.find(
        o => !o.isFakeIpRoute && o.ip !== fakeIpOutcome.ip
      );
      if (nonFakeOutcome) {
        this.directIp = nonFakeOutcome.ip;
      }
      return fakeIpOutcome.ip;
    }

    // 3. Signal B: If one of the simultaneously returned IPs matches a user-configured allowed VPN IP,
    //    then that tunnel is actively routing traffic right now and the other IP is the direct Home IP.
    const allowedList = this.getAllowedIps ? this.getAllowedIps() : [];
    if (allowedList.length > 0) {
      const matchedAllowed = orderedIps.find(ip => allowedList.includes(ip));
      if (matchedAllowed) {
        const otherIp = uniqueIps.find(ip => ip !== matchedAllowed);
        if (otherIp && !allowedList.includes(otherIp)) {
          this.directIp = otherIp;
        }
        return matchedAllowed;
      }
    }

    // 4. Signal C: In RF VPN configs (Happ / Xray), .ru / Yandex goes DIRECT (Home IP) while foreign endpoints go via VPN.
    //    If Yandex returned an IP without FakeIP and foreign endpoints returned a different IP, Yandex's IP is directIp!
    const foreignOutcomes = [
      results.cfElectron,
      results.cfNode,
      results.ipify,
      results.icanhazip,
      results.aws
    ].filter((item): item is { ip: string; isFakeIpRoute: boolean } => Boolean(item.ip));

    if (
      yandexOutcome.ip &&
      !yandexOutcome.isFakeIpRoute &&
      foreignOutcomes.some(f => f.ip !== yandexOutcome.ip)
    ) {
      this.directIp = yandexOutcome.ip;
    }

    // 5. Signal D: If we still don't know which of the IPs is the physical ISP (directIp), probe via the physical LAN NIC
    if (!this.directIp || !uniqueIps.includes(this.directIp)) {
      const probedDirect = await this.probeDirectPhysicalIp();
      if (probedDirect) {
        this.directIp = probedDirect;
      }
    }

    if (this.directIp) {
      const vpnCandidates = orderedIps.filter(ip => ip !== this.directIp);
      if (vpnCandidates.length > 0) {
        return vpnCandidates[0];
      }
    }

    // 6. Fallback priority: Chromium network stack (respects Windows System Proxy) -> Cloudflare (AI route) -> first valid
    return results.cfElectron.ip || results.cfNode.ip || uniqueIps[0];
  }

  /**
   * Probes the public IP bound explicitly to the physical LAN adapter (Wi-Fi / Ethernet)
   * so we can distinguish the ISP Home IP from the VPN Tunnel IP even if IPShield started with VPN already on.
   * Includes Yandex Internetometer first so it works reliably inside RF even if foreign checkers are blocked on the direct link.
   */
  private async probeDirectPhysicalIp(): Promise<string | null> {
    const physicalLanIp = this.getPhysicalLanIp();
    if (!physicalLanIp) {
      return null;
    }

    const ipv4Parser = (body: string): string | null => {
      const trimmed = body.trim().replace(/^["']+|["']+$/g, '');
      const ipv4Regex =
        /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
      return ipv4Regex.test(trimmed) ? trimmed : null;
    };

    const [yandexDirect, ipifyDirect, awsDirect] = await Promise.all([
      this.fetchHttp('https://internet.yandex.net/internet/api/v0/ip', ipv4Parser, physicalLanIp),
      this.fetchHttp('https://api.ipify.org', ipv4Parser, physicalLanIp),
      this.fetchHttp('https://checkip.amazonaws.com', ipv4Parser, physicalLanIp)
    ]);

    return yandexDirect.ip || ipifyDirect.ip || awsDirect.ip || null;
  }

  /**
   * Detects whether a virtual TUN / VPN interface (utun, wintun, Happ, Sing-box, FakeIP 198.18.0.0/15) is currently active.
   */
  private hasActiveTunnelInterface(): boolean {
    const nets = os.networkInterfaces();
    const tunNameRegex =
      /^(utun|tun|tap|ppp|wg|wireguard|wintun|happ|sing-box|xray|v2ray|clash|nekoray|hiddify|amnezia|openvpn|outline|proton|nord|mullvad|tailscale|zerotier)/i;

    for (const name of Object.keys(nets)) {
      const list = nets[name] || [];
      for (const item of list) {
        if (item.internal || item.family !== 'IPv4') continue;
        if (
          tunNameRegex.test(name) ||
          item.address.startsWith('198.18.') ||
          item.address.startsWith('198.19.') ||
          item.mac === '00:00:00:00:00:00'
        ) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Finds the local IPv4 address of the physical Wi-Fi / Ethernet adapter (excluding virtual TUN adapters).
   */
  private getPhysicalLanIp(): string | null {
    const nets = os.networkInterfaces();
    const virtualNameRegex =
      /^(utun|tun|tap|ppp|wg|wireguard|wintun|happ|sing-box|xray|v2ray|clash|nekoray|hiddify|amnezia|openvpn|outline|proton|nord|mullvad|tailscale|zerotier|vethernet|vmware|vbox|docker|wsl|hyper-v|loopback)/i;

    for (const name of Object.keys(nets)) {
      if (virtualNameRegex.test(name)) continue;
      const list = nets[name] || [];
      for (const item of list) {
        if (item.internal || item.family !== 'IPv4') continue;
        if (!item.mac || item.mac === '00:00:00:00:00:00') continue;
        if (
          item.address.startsWith('198.18.') ||
          item.address.startsWith('198.19.') ||
          item.address.startsWith('169.254.')
        ) {
          continue;
        }
        return item.address;
      }
    }
    return null;
  }

  /**
   * Flushes OS user-space DNS cache without requiring sudo/admin privileges.
   */
  private flushUserDnsCache(): Promise<void> {
    return new Promise(resolve => {
      if (process.platform === 'darwin') {
        execFile('/usr/bin/dscacheutil', ['-flushcache'], { timeout: 1000 }, () => resolve());
      } else if (process.platform === 'win32') {
        execFile(
          'ipconfig',
          ['/flushdns'],
          { timeout: 1500, windowsHide: true },
          () => resolve()
        );
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
   * Chromium network stack request helper (Electron main process).
   * Respects Windows System Proxy (Internet Settings) and Chromium HostResolver, matching Browser behavior.
   */
  private async fetchViaElectronNet(
    baseUrl: string,
    parseFn: (text: string) => string | null
  ): Promise<string | null> {
    const el = getElectronNet();
    if (!el) return null;

    try {
      const probeSession = el.session.fromPartition('ipshield-ip-probe', { cache: false });
      await probeSession.clearHostResolverCache();
      await probeSession.closeAllConnections();

      return await new Promise<string | null>(resolve => {
        let settled = false;
        const done = (val: string | null) => {
          if (settled) return;
          settled = true;
          clearTimeout(hardTimer);
          resolve(val);
        };

        const urlWithBust = `${baseUrl}?_=${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
        const req = el.net.request({
          method: 'GET',
          url: urlWithBust,
          session: probeSession,
          redirect: 'follow',
          useSessionCookies: false
        });

        req.setHeader('Connection', 'close');
        req.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        req.setHeader('Pragma', 'no-cache');
        req.setHeader('User-Agent', 'IPShield/1.0');

        const hardTimer = setTimeout(() => {
          try {
            req.abort();
          } catch {
            // ignore
          }
          done(null);
        }, 2200);

        req.on('response', res => {
          let body = '';
          res.on('data', (chunk: Buffer) => {
            body += chunk.toString('utf-8');
            if (body.length > 8192) {
              try {
                req.abort();
              } catch {
                // ignore
              }
              done(null);
            }
          });
          res.on('end', () => {
            done(parseFn(body));
          });
          res.on('error', () => done(null));
        });

        req.on('error', () => done(null));
        req.end();
      });
    } catch {
      return null;
    }
  }

  /**
   * Unified HTTP request helper with IPv4 family pinning and bounded response size (Q-2, B-4).
   * Also inspects socket remoteAddress to detect RFC 2544 FakeIP (198.18.0.0/15) VPN routing.
   */
  private fetchHttp(
    baseUrl: string,
    parseFn: (text: string) => string | null,
    localAddress?: string
  ): Promise<ProbeOutcome> {
    return new Promise(resolve => {
      let settled = false;
      const done = (val: ProbeOutcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(hardTimer);
        resolve(val);
      };

      const urlWithBust = `${baseUrl}?_=${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
      const req = https.get(
        urlWithBust,
        {
          family: 4, // B-4: Force IPv4 resolution to prevent v4/v6 provider flapping
          agent: false,
          ...(localAddress ? { localAddress } : {}),
          timeout: 2000,
          headers: {
            Connection: 'close',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            Pragma: 'no-cache',
            'User-Agent': 'IPShield/1.0'
          }
        },
        res => {
          const remoteAddr = res.socket?.remoteAddress || '';
          const isFakeIpRoute =
            remoteAddr.startsWith('198.18.') ||
            remoteAddr.startsWith('198.19.') ||
            remoteAddr.startsWith('::ffff:198.18.') ||
            remoteAddr.startsWith('::ffff:198.19.');

          let body = '';
          const maxBytes = 8192; // Prevent excessive data allocation
          res.on('data', chunk => {
            body += chunk;
            if (body.length > maxBytes) {
              res.destroy();
              done({ ip: null, isFakeIpRoute: false });
            }
          });
          res.on('end', () => {
            res.destroy();
            done({ ip: parseFn(body), isFakeIpRoute });
          });
          res.on('error', () => done({ ip: null, isFakeIpRoute: false }));
        }
      );

      const hardTimer = setTimeout(() => {
        try {
          req.destroy();
        } catch {
          // ignore
        }
        done({ ip: null, isFakeIpRoute: false });
      }, 2200);

      req.on('error', () => done({ ip: null, isFakeIpRoute: false }));
      req.on('timeout', () => {
        try {
          req.destroy();
        } catch {
          // ignore
        }
        done({ ip: null, isFakeIpRoute: false });
      });
    });
  }
}

