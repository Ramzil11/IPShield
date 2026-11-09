import fs from 'fs';
import path from 'path';
import os from 'os';
import { app } from 'electron';
import { Store } from './store';

export interface AutoLaunchAdapter {
  setLoginItemSettings?: (settings: {
    openAtLogin: boolean;
    openAsHidden?: boolean;
    path?: string;
    args?: string[];
  }) => void;
  getLoginItemSettings?: (options?: { path?: string; args?: string[] }) => {
    openAtLogin: boolean;
    wasOpenedAtLogin?: boolean;
    wasOpenedAsHidden?: boolean;
  };
  isPackaged?: boolean;
}

export interface AutoLaunchOptions {
  appName?: string;
  platform?: NodeJS.Platform;
  adapter?: AutoLaunchAdapter;
  linuxAutostartDir?: string;
}

export class AutoLaunchManager {
  private store: Store;
  private appName: string;
  private platform: NodeJS.Platform;
  private adapter: AutoLaunchAdapter;
  private customLinuxAutostartDir?: string;

  constructor(store: Store, options?: AutoLaunchOptions) {
    this.store = store;
    this.appName = options?.appName || (app && typeof app.getName === 'function' ? app.getName() : 'IPShield');
    this.platform = options?.platform || process.platform;
    this.customLinuxAutostartDir = options?.linuxAutostartDir;
    this.adapter = options?.adapter || {
      setLoginItemSettings:
        app && typeof app.setLoginItemSettings === 'function'
          ? settings => app.setLoginItemSettings(settings)
          : undefined,
      getLoginItemSettings:
        app && typeof app.getLoginItemSettings === 'function'
          ? opts => app.getLoginItemSettings(opts)
          : undefined,
      isPackaged: app && typeof app.isPackaged === 'boolean' ? app.isPackaged : false
    };
  }

  public init(): void {
    const enabled = this.isEnabled();
    this.apply(enabled);
  }

  public isEnabled(): boolean {
    const storeVal = this.store.getState().settings.autoLaunch;
    if (typeof storeVal === 'boolean') {
      return storeVal;
    }

    if (this.platform === 'linux') {
      return this.isLinuxDesktopInstalled();
    }

    if (this.adapter.getLoginItemSettings) {
      try {
        const s = this.adapter.getLoginItemSettings();
        if (typeof s?.openAtLogin === 'boolean') {
          return s.openAtLogin;
        }
      } catch {
        // ignore
      }
    }

    return true;
  }

  public setEnabled(enabled: boolean): boolean {
    this.store.updateSettings({ autoLaunch: enabled });
    return this.apply(enabled);
  }

  public toggle(): boolean {
    const next = !this.isEnabled();
    this.setEnabled(next);
    return next;
  }

  public apply(enabled: boolean): boolean {
    if (this.platform === 'darwin') {
      return this.applyDarwin(enabled);
    } else if (this.platform === 'win32') {
      return this.applyWindows(enabled);
    } else {
      return this.applyLinux(enabled);
    }
  }

  private applyDarwin(enabled: boolean): boolean {
    if (this.adapter.setLoginItemSettings) {
      try {
        this.adapter.setLoginItemSettings({
          openAtLogin: enabled,
          openAsHidden: true
        });
        return true;
      } catch (err) {
        console.warn('[AutoLaunch] Darwin setLoginItemSettings warning:', err);
        return false;
      }
    }
    return false;
  }

  private applyWindows(enabled: boolean): boolean {
    if (this.adapter.setLoginItemSettings) {
      try {
        const execPath = process.execPath;
        this.adapter.setLoginItemSettings({
          openAtLogin: enabled,
          path: execPath,
          args: ['--hidden']
        });
        return true;
      } catch (err) {
        console.warn('[AutoLaunch] Windows setLoginItemSettings warning:', err);
        return false;
      }
    }
    return false;
  }

  public getLinuxAutostartDir(): string {
    if (this.customLinuxAutostartDir) {
      return this.customLinuxAutostartDir;
    }
    const configDir = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
    return path.join(configDir, 'autostart');
  }

  public getLinuxDesktopPath(): string {
    return path.join(this.getLinuxAutostartDir(), `${this.appName.toLowerCase()}.desktop`);
  }

  public isLinuxDesktopInstalled(): boolean {
    try {
      return fs.existsSync(this.getLinuxDesktopPath());
    } catch {
      return false;
    }
  }

  public generateLinuxDesktopContent(): string {
    const execPath = process.env.APPIMAGE || process.execPath;
    let execLine: string;

    if (this.adapter.isPackaged) {
      execLine = `"${execPath}" --hidden`;
    } else {
      const entryScript = path.resolve(process.argv[1] || '.');
      execLine = `"${execPath}" "${entryScript}" --hidden`;
    }

    return [
      '[Desktop Entry]',
      'Type=Application',
      'Version=1.0',
      `Name=${this.appName}`,
      'Comment=Strict IP-bound firewall and process guard',
      `Exec=${execLine}`,
      'Icon=ipshield',
      'Terminal=false',
      'StartupNotify=false',
      'Categories=Utility;Security;Network;',
      'X-GNOME-Autostart-enabled=true',
      ''
    ].join('\n');
  }

  private applyLinux(enabled: boolean): boolean {
    let success = false;
    const desktopPath = this.getLinuxDesktopPath();
    const desktopDir = path.dirname(desktopPath);

    try {
      if (enabled) {
        if (!fs.existsSync(desktopDir)) {
          fs.mkdirSync(desktopDir, { recursive: true });
        }
        const content = this.generateLinuxDesktopContent();
        fs.writeFileSync(desktopPath, content, { encoding: 'utf-8', mode: 0o755 });
        success = true;
      } else {
        if (fs.existsSync(desktopPath)) {
          fs.unlinkSync(desktopPath);
        }
        success = true;
      }
    } catch (err) {
      console.warn('[AutoLaunch] Linux autostart file management warning:', err);
    }

    if (this.adapter.setLoginItemSettings) {
      try {
        this.adapter.setLoginItemSettings({ openAtLogin: enabled });
      } catch {
        // ignore
      }
    }

    return success;
  }
}
