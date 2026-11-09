import fs from 'fs';
import os from 'os';
import path from 'path';
import https from 'https';
import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import { UpdatePhase, UpdateStatusInfo } from '../shared/types';

const execFileAsync = promisify(execFile);

export interface GithubReleaseAsset {
  name: string;
  browser_download_url: string;
  size?: number;
}

export interface GithubReleasePayload {
  tag_name: string;
  html_url: string;
  draft?: boolean;
  prerelease?: boolean;
  assets?: GithubReleaseAsset[];
}

export interface UpdaterOptions {
  repo?: string;
  currentVersion?: string;
  platform?: NodeJS.Platform;
  arch?: string;
  nowFn?: () => number;
  fetchReleaseFn?: () => Promise<GithubReleasePayload>;
  downloadFileFn?: (
    url: string,
    destPath: string,
    onProgress: (percent: number) => void
  ) => Promise<void>;
  prepareExtractedAppFn?: (downloadedFilePath: string) => Promise<string>;
}

const DISMISS_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const POLL_INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours
const INITIAL_DELAY_MS = 3000; // 3 seconds after app startup

/**
 * Strips leading 'v'/'V' and returns normalized semver string (e.g. "1.0.2") or null.
 */
export function normalizeSemver(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const cleaned = raw.trim().replace(/^[vV]/, '').split('-')[0];
  if (!/^\d+\.\d+\.\d+$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

/**
 * Compares two semantic version strings.
 * Returns 1 if a > b, -1 if a < b, 0 if equal.
 */
export function compareSemver(a: string, b: string): number {
  const normA = normalizeSemver(a);
  const normB = normalizeSemver(b);
  if (!normA || !normB) return 0;

  const partsA = normA.split('.').map(Number);
  const partsB = normB.split('.').map(Number);

  for (let i = 0; i < 3; i++) {
    const diff = (partsA[i] || 0) - (partsB[i] || 0);
    if (diff > 0) return 1;
    if (diff < 0) return -1;
  }
  return 0;
}

/**
 * Selects the best release asset from GitHub Release assets for the current OS and CPU architecture.
 */
export function selectBestAsset(
  assets: GithubReleaseAsset[],
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch
): GithubReleaseAsset | null {
  if (!Array.isArray(assets) || assets.length === 0) return null;

  const lowerArch = arch.toLowerCase();

  if (platform === 'darwin') {
    const zips = assets.filter(a => a.name.toLowerCase().endsWith('.zip'));
    let archZip = zips.find(a => a.name.toLowerCase().includes(lowerArch));
    if (!archZip && (lowerArch === 'x64' || lowerArch === 'x86_64')) {
      // electron-builder defaults x64 macOS zip to "${productName}-${version}-mac.zip" without "x64" in filename
      archZip = zips.find(a => !a.name.toLowerCase().includes('arm64'));
    }
    if (archZip) return archZip;
    if (zips.length > 0) return zips[0];

    const dmgs = assets.filter(a => a.name.toLowerCase().endsWith('.dmg'));
    let archDmg = dmgs.find(a => a.name.toLowerCase().includes(lowerArch));
    if (!archDmg && (lowerArch === 'x64' || lowerArch === 'x86_64')) {
      archDmg = dmgs.find(a => !a.name.toLowerCase().includes('arm64'));
    }
    if (archDmg) return archDmg;
    if (dmgs.length > 0) return dmgs[0];
    return null;
  }

  if (platform === 'win32') {
    const exes = assets.filter(a => a.name.toLowerCase().endsWith('.exe'));
    const setupExe = exes.find(
      a => a.name.toLowerCase().includes('setup') && !a.name.toLowerCase().includes('portable')
    );
    if (setupExe) return setupExe;
    const nonPortableExe = exes.find(a => !a.name.toLowerCase().includes('portable'));
    if (nonPortableExe) return nonPortableExe;
    if (exes.length > 0) return exes[0];
    return null;
  }

  return assets[0] || null;
}

function readPackageVersionFallback(): string {
  try {
    const pkgPath = path.join(__dirname, '../../package.json');
    const raw = fs.readFileSync(pkgPath, 'utf-8');
    const parsed = JSON.parse(raw) as { version?: string };
    return parsed.version || '1.0.0';
  } catch {
    return '1.0.0';
  }
}

export class AppUpdater {
  private readonly repo: string;
  private readonly currentVersion: string;
  private readonly platform: NodeJS.Platform;
  private readonly arch: string;
  private readonly nowFn: () => number;
  private readonly customFetchRelease?: () => Promise<GithubReleasePayload>;
  private readonly customDownloadFile?: (
    url: string,
    destPath: string,
    onProgress: (percent: number) => void
  ) => Promise<void>;
  private readonly customPrepareExtractedApp?: (downloadedFilePath: string) => Promise<string>;

  private phase: UpdatePhase = 'idle';
  private latestVersion: string | null = null;
  private releaseUrl: string | null = null;
  private assetDownloadUrl: string | null = null;
  private assetFileName: string | null = null;
  private downloadProgress = 0;
  private error: string | null = null;

  private dismissedVersion: string | null = null;
  private dismissedUntil = 0;

  private readyInstallTarget: string | null = null;
  private pollTimer: NodeJS.Timeout | null = null;
  private initialTimer: NodeJS.Timeout | null = null;
  private listeners: Array<(status: UpdateStatusInfo) => void> = [];

  constructor(options: UpdaterOptions = {}) {
    this.repo = options.repo || 'Ramzil11/IPShield';
    this.currentVersion =
      normalizeSemver(options.currentVersion || '') ||
      normalizeSemver(readPackageVersionFallback()) ||
      '1.0.0';
    this.platform = options.platform || process.platform;
    this.arch = options.arch || process.arch;
    this.nowFn = options.nowFn || (() => Date.now());
    this.customFetchRelease = options.fetchReleaseFn;
    this.customDownloadFile = options.downloadFileFn;
    this.customPrepareExtractedApp = options.prepareExtractedAppFn;
  }

  public onStatusChange(listener: (status: UpdateStatusInfo) => void): void {
    this.listeners.push(listener);
  }

  private notify(): void {
    const status = this.getStatus();
    for (const listener of this.listeners) {
      try {
        listener(status);
      } catch {
        // ignore listener errors
      }
    }
  }

  private isCurrentlyDismissed(): boolean {
    if (!this.latestVersion || !this.dismissedVersion) return false;
    if (this.dismissedVersion !== this.latestVersion) return false;
    return this.nowFn() < this.dismissedUntil;
  }

  public getStatus(): UpdateStatusInfo {
    return {
      phase: this.phase,
      currentVersion: this.currentVersion,
      latestVersion: this.latestVersion,
      releaseUrl: this.releaseUrl,
      downloadProgress: this.downloadProgress,
      dismissed: this.isCurrentlyDismissed(),
      error: this.error
    };
  }

  public start(
    initialDelayMs: number = INITIAL_DELAY_MS,
    pollIntervalMs: number = POLL_INTERVAL_MS
  ): void {
    this.stop();
    this.initialTimer = setTimeout(() => {
      void this.checkForUpdates(false);
    }, initialDelayMs);

    this.pollTimer = setInterval(() => {
      void this.checkForUpdates(false);
    }, pollIntervalMs);
  }

  public stop(): void {
    if (this.initialTimer) {
      clearTimeout(this.initialTimer);
      this.initialTimer = null;
    }
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  /**
   * Dismisses the update banner for the current latestVersion for 24 hours
   * (or until the app is restarted or a newer version is released).
   */
  public dismissUpdate(): UpdateStatusInfo {
    if (this.latestVersion) {
      this.dismissedVersion = this.latestVersion;
      this.dismissedUntil = this.nowFn() + DISMISS_DURATION_MS;
    }
    if (this.phase === 'error') {
      this.phase = this.latestVersion ? 'available' : 'idle';
      this.error = null;
    }
    this.notify();
    return this.getStatus();
  }

  /**
   * Checks GitHub Releases for a newer version.
   * @param manual If true, resets any 24h dismiss state so the banner appears immediately.
   */
  public async checkForUpdates(manual: boolean = false): Promise<UpdateStatusInfo> {
    if (this.phase === 'downloading' || this.phase === 'ready') {
      if (manual) {
        this.dismissedVersion = null;
        this.dismissedUntil = 0;
        this.notify();
      }
      return this.getStatus();
    }

    if (manual) {
      this.dismissedVersion = null;
      this.dismissedUntil = 0;
    }

    try {
      const release = this.customFetchRelease
        ? await this.customFetchRelease()
        : await this.fetchLatestGithubRelease();

      if (!release || release.draft || release.prerelease) {
        return this.getStatus();
      }

      const remoteVer = normalizeSemver(release.tag_name);
      if (!remoteVer) {
        return this.getStatus();
      }

      if (compareSemver(remoteVer, this.currentVersion) > 0) {
        const asset = selectBestAsset(release.assets || [], this.platform, this.arch);
        this.latestVersion = remoteVer;
        this.releaseUrl =
          release.html_url || `https://github.com/${this.repo}/releases/tag/v${remoteVer}`;
        this.assetDownloadUrl = asset ? asset.browser_download_url : null;
        this.assetFileName = asset ? asset.name : null;
        this.phase = 'available';
        this.error = null;
      } else {
        this.latestVersion = null;
        this.releaseUrl = null;
        this.assetDownloadUrl = null;
        this.assetFileName = null;
        this.phase = 'idle';
        this.error = null;
      }
    } catch {
      // Silent failure during background polling so we don't bother the user when offline
    }

    this.notify();
    return this.getStatus();
  }

  /**
   * Downloads the release asset and prepares it for one-click installation.
   */
  public async startDownload(): Promise<UpdateStatusInfo> {
    if (this.phase === 'downloading') {
      return this.getStatus();
    }

    if (!this.latestVersion) {
      await this.checkForUpdates(true);
    }

    if (!this.assetDownloadUrl || !this.assetFileName) {
      this.phase = 'error';
      this.error = 'Пакет обновления для вашей ОС не найден в релизе';
      this.notify();
      return this.getStatus();
    }

    this.dismissedVersion = null;
    this.dismissedUntil = 0;
    this.phase = 'downloading';
    this.downloadProgress = 0;
    this.error = null;
    this.notify();

    try {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-update-'));
      const safeFileName = path.basename(this.assetFileName).replace(/[^a-zA-Z0-9._ -]/g, '_');
      const downloadedPath = path.join(tmpDir, safeFileName);

      const onProgress = (pct: number) => {
        const clamped = Math.max(0, Math.min(100, Math.round(pct)));
        if (clamped !== this.downloadProgress) {
          this.downloadProgress = clamped;
          this.notify();
        }
      };

      if (this.customDownloadFile) {
        await this.customDownloadFile(this.assetDownloadUrl, downloadedPath, onProgress);
      } else {
        await this.downloadFileWithRedirects(this.assetDownloadUrl, downloadedPath, onProgress);
      }

      if (this.customPrepareExtractedApp) {
        this.readyInstallTarget = await this.customPrepareExtractedApp(downloadedPath);
      } else if (this.platform === 'darwin' && downloadedPath.toLowerCase().endsWith('.zip')) {
        this.readyInstallTarget = await this.extractMacZipBundle(downloadedPath, tmpDir);
      } else {
        this.readyInstallTarget = downloadedPath;
      }

      this.downloadProgress = 100;
      this.phase = 'ready';
      this.error = null;
      this.notify();
    } catch (err) {
      this.phase = 'error';
      this.error = err instanceof Error ? err.message : 'Не удалось скачать обновление';
      this.notify();
    }

    return this.getStatus();
  }

  /**
   * Installs the prepared update and restarts the application.
   */
  public async applyUpdateAndRestart(beforeQuitCleanup: () => Promise<void>): Promise<void> {
    if (this.phase !== 'ready' || !this.readyInstallTarget) {
      return;
    }

    const targetPath = this.readyInstallTarget;
    await beforeQuitCleanup();

    if (this.platform === 'darwin') {
      if (targetPath.endsWith('.app')) {
        const currentBundlePath = this.resolveCurrentMacAppBundlePath();
        const destAppPath = currentBundlePath || '/Applications/IPShield.app';
        const pid = process.pid;

        // Detached helper script that waits for the current process to exit,
        // replaces the .app bundle, strips quarantine, and relaunches IPShield.
        const script = [
          'for i in $(seq 1 30); do',
          `  if ! kill -0 ${pid} 2>/dev/null; then break; fi`,
          '  sleep 0.2',
          'done',
          `rm -rf "${destAppPath}" && mv -f "${targetPath}" "${destAppPath}"`,
          `/usr/bin/xattr -cr "${destAppPath}" >/dev/null 2>&1 || true`,
          `open -n "${destAppPath}"`
        ].join('\n');

        const child = spawn('/bin/sh', ['-c', script], {
          detached: true,
          stdio: 'ignore'
        });
        child.unref();
      } else {
        // Fallback if asset is a .dmg
        const child = spawn('/usr/bin/open', [targetPath], {
          detached: true,
          stdio: 'ignore'
        });
        child.unref();
      }
      return;
    }

    if (this.platform === 'win32') {
      const child = spawn(targetPath, ['/S'], {
        detached: true,
        stdio: 'ignore'
      });
      child.unref();
    }
  }

  private resolveCurrentMacAppBundlePath(): string | null {
    const execPath = process.execPath;
    const marker = '.app/Contents/MacOS/';
    const idx = execPath.indexOf(marker);
    if (idx !== -1) {
      return execPath.slice(0, idx + 4);
    }
    return null;
  }

  private async extractMacZipBundle(zipPath: string, tmpDir: string): Promise<string> {
    const extractDir = path.join(tmpDir, 'extracted');
    fs.mkdirSync(extractDir, { recursive: true });

    await execFileAsync('/usr/bin/ditto', ['-x', '-k', zipPath, extractDir]);

    const entries = fs.readdirSync(extractDir);
    const appFolder = entries.find(e => e.toLowerCase().endsWith('.app'));
    if (!appFolder) {
      throw new Error('В архиве обновления не найден пакет IPShield.app');
    }

    const fullAppPath = path.join(extractDir, appFolder);
    try {
      await execFileAsync('/usr/bin/xattr', ['-cr', fullAppPath]);
    } catch {
      // ignore if xattr is not needed
    }
    return fullAppPath;
  }

  private fetchLatestGithubRelease(): Promise<GithubReleasePayload> {
    const url = `https://api.github.com/repos/${this.repo}/releases/latest`;
    return new Promise((resolve, reject) => {
      const req = https.get(
        url,
        {
          headers: {
            'User-Agent': `IPShield/${this.currentVersion}`,
            Accept: 'application/vnd.github+json'
          },
          timeout: 10000
        },
        res => {
          if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            res.resume();
            this.fetchJsonFromUrl(res.headers.location).then(resolve).catch(reject);
            return;
          }

          if (res.statusCode !== 200) {
            res.resume();
            reject(new Error(`GitHub API HTTP ${res.statusCode}`));
            return;
          }

          let body = '';
          res.setEncoding('utf8');
          res.on('data', chunk => {
            body += chunk;
          });
          res.on('end', () => {
            try {
              resolve(JSON.parse(body) as GithubReleasePayload);
            } catch (e) {
              reject(e);
            }
          });
        }
      );

      req.on('timeout', () => {
        req.destroy(new Error('GitHub API request timeout'));
      });
      req.on('error', reject);
    });
  }

  private fetchJsonFromUrl(url: string): Promise<GithubReleasePayload> {
    return new Promise((resolve, reject) => {
      const req = https.get(
        url,
        {
          headers: {
            'User-Agent': `IPShield/${this.currentVersion}`,
            Accept: 'application/vnd.github+json'
          },
          timeout: 10000
        },
        res => {
          if (res.statusCode !== 200) {
            res.resume();
            reject(new Error(`GitHub API HTTP ${res.statusCode}`));
            return;
          }
          let body = '';
          res.setEncoding('utf8');
          res.on('data', chunk => {
            body += chunk;
          });
          res.on('end', () => {
            try {
              resolve(JSON.parse(body) as GithubReleasePayload);
            } catch (e) {
              reject(e);
            }
          });
        }
      );
      req.on('error', reject);
    });
  }

  private downloadFileWithRedirects(
    url: string,
    destPath: string,
    onProgress: (percent: number) => void,
    redirectCount: number = 0
  ): Promise<void> {
    if (redirectCount > 6) {
      return Promise.reject(new Error('Too many redirects while downloading update'));
    }

    return new Promise((resolve, reject) => {
      const req = https.get(
        url,
        {
          headers: {
            'User-Agent': `IPShield/${this.currentVersion}`,
            Accept: 'application/octet-stream'
          },
          timeout: 30000
        },
        res => {
          if (
            res.statusCode &&
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            res.resume();
            this.downloadFileWithRedirects(
              res.headers.location,
              destPath,
              onProgress,
              redirectCount + 1
            )
              .then(resolve)
              .catch(reject);
            return;
          }

          if (res.statusCode !== 200) {
            res.resume();
            reject(new Error(`HTTP ${res.statusCode} при скачивании обновления`));
            return;
          }

          const totalBytes = Number(res.headers['content-length'] || 0);
          let receivedBytes = 0;

          const fileStream = fs.createWriteStream(destPath);

          res.on('data', (chunk: Buffer) => {
            receivedBytes += chunk.length;
            if (totalBytes > 0) {
              onProgress((receivedBytes / totalBytes) * 100);
            }
          });

          res.pipe(fileStream);

          fileStream.on('finish', () => {
            fileStream.close(() => resolve());
          });

          fileStream.on('error', err => {
            fs.rmSync(destPath, { force: true });
            reject(err);
          });
        }
      );

      req.on('timeout', () => {
        req.destroy(new Error('Таймаут при скачивании обновления'));
      });
      req.on('error', err => {
        fs.rmSync(destPath, { force: true });
        reject(err);
      });
    });
  }
}
