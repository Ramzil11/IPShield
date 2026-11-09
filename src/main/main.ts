import path from 'path';
import fs from 'fs';
import { pathToFileURL } from 'url';
import { app, BrowserWindow, ipcMain, Menu, nativeImage, shell, Tray } from 'electron';
import { Store } from './store';
import { IpMonitor } from './ipMonitor';
import { ProcessGuard } from './processGuard';
import { DomainFirewall } from './domainFirewall';
import { AppUpdater } from './updater';
import { AutoLaunchManager } from './autoLaunch';
import { scanAvailableApps } from './appScanner';
import { RuleRuntimeStatus, RuntimeSnapshot, ShieldRule } from '../shared/types';
import {
  validateAndSanitizeRule,
  validateAndSanitizeIpEntry
} from '../shared/validation';

if (app && typeof app.setName === 'function') {
  app.setName('IPShield');
}

if (app && typeof app.requestSingleInstanceLock === 'function') {
  const gotTheLock = app.requestSingleInstanceLock();
  if (!gotTheLock) {
    app.quit();
  } else {
    app.on('second-instance', () => {
      showMainWindow();
    });
  }
}

let tray: Tray | null = null;
let mainWindow: BrowserWindow | null = null;
let isQuitting = false;

const store = new Store();
const autoLaunchManager = new AutoLaunchManager(store);
const ipMonitor = new IpMonitor(() => store.getState().ips.map(e => e.ip));
const processGuard = new ProcessGuard();
const domainFirewall = new DomainFirewall();
const appUpdater = new AppUpdater({
  currentVersion: app && typeof app.getVersion === 'function' ? app.getVersion() : undefined
});

let cachedFrozenByRule: Record<string, number[]> = {};
let enforceTimer: NodeJS.Timeout | null = null;
let lastBroadcastSignature = '';
let lastTraySignature = '';

/**
 * Generates a crisp Retina 36x36 (@2x -> 18x18pt) Shield icon for the Menu Bar / System Tray,
 * colored dynamically (Green / Amber / Red) based on protection status.
 */
function createShieldTrayIcon(colorHex: string): Electron.NativeImage {
  const size = 36;
  const buf = Buffer.alloc(size * size * 4, 0);

  const hex = colorHex.replace('#', '');
  const r = parseInt(hex.slice(0, 2), 16) || 56;
  const g = parseInt(hex.slice(2, 4), 16) || 189;
  const b = parseInt(hex.slice(4, 6), 16) || 248;

  const setPixel = (x: number, y: number, alpha: number) => {
    if (x < 0 || x >= size || y < 0 || y >= size || alpha <= 0) return;
    const a = Math.min(1, Math.max(0, alpha));
    const idx = (y * size + x) * 4;
    buf[idx] = Math.round(b * a);
    buf[idx + 1] = Math.round(g * a);
    buf[idx + 2] = Math.round(r * a);
    buf[idx + 3] = Math.round(a * 255);
  };

  // Classic heraldic shield SDF:
  // Top y = 4, bottom tip y = 32, center x = 17.5
  const shieldSignedDistance = (px: number, py: number): number => {
    const cx = 17.5;
    const topY = 4.5;
    const botY = 31.5;

    if (py < topY - 2 || py > botY + 2) {
      return Math.max(topY - py, py - botY);
    }

    const t = Math.max(0, Math.min(1, (py - topY) / (botY - topY)));
    // Shield half-width profile: wide at top (12.5px), curving smoothly to a point (0px) at bottom
    const halfWidth = 12.5 * Math.pow(1 - Math.pow(t, 1.85), 0.72);
    const dx = Math.abs(px - cx) - halfWidth;

    // Slight arch on the top edge
    const topArch = topY + 1.2 * Math.pow(Math.abs(px - cx) / 12.5, 2);
    const dyTop = topArch - py;
    const dyBot = py - botY;

    return Math.max(dx, dyTop, dyBot);
  };

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const d = shieldSignedDistance(x, y);
      if (d <= 0.8) {
        // Anti-aliased outer edge
        const edgeCoverage = Math.min(1, Math.max(0, 0.8 - d));

        // Outer border thickness ~ 2.4px
        const isBorder = d >= -2.4;
        // Inner vertical half-shield highlight (classic security shield split)
        const isRightHalfInner = d < -4.2 && x >= 17.5;

        let alpha = 0;
        if (isBorder) {
          alpha = 0.98 * edgeCoverage;
        } else if (isRightHalfInner) {
          alpha = 0.78;
        } else {
          alpha = 0.28;
        }

        setPixel(x, y, alpha);
      }
    }
  }

  return nativeImage.createFromBitmap(buf, {
    width: size,
    height: size,
    scaleFactor: 2.0
  });
}

function computeAllowedMap(currentIp: string): Record<string, boolean> {
  const { rules, ips } = store.getState();
  const map: Record<string, boolean> = {};
  const matchedIpEntry = ips.find(item => item.ip === currentIp);

  for (const rule of rules) {
    if (matchedIpEntry && matchedIpEntry.ruleIds.includes(rule.id)) {
      map[rule.id] = true;
    } else {
      map[rule.id] = false;
    }
  }
  return map;
}

function buildSnapshot(): RuntimeSnapshot {
  const { rules, ips } = store.getState();
  const currentIp = ipMonitor.getCurrentIp();
  const allowedMap = computeAllowedMap(currentIp);
  const ruleStatuses: Record<string, RuleRuntimeStatus> = {};

  for (const r of rules) {
    ruleStatuses[r.id] = {
      ruleId: r.id,
      allowed: Boolean(allowedMap[r.id]),
      frozenPids: cachedFrozenByRule[r.id] || []
    };
  }

  return {
    currentIp,
    ipChecking: ipMonitor.isBusy(),
    lastCheckedAt: Date.now(),
    rules,
    ips,
    ruleStatuses,
    firewallElevated: domainFirewall.isElevated(),
    firewallError: domainFirewall.getLastError(),
    processGuardError: processGuard.getLastError(),
    update: appUpdater.getStatus(),
    autoLaunch: autoLaunchManager.isEnabled()
  };
}

function updateTrayAppearance(snapshot: RuntimeSnapshot): void {
  if (!tray) return;

  const totalRules = snapshot.rules.length;
  const openCount = snapshot.rules.filter(r => snapshot.ruleStatuses[r.id]?.allowed).length;

  let color = '#EF4444'; // Red (Blocked)
  let statusText = 'Заблокировано';

  if (totalRules === 0) {
    color = '#F59E0B'; // Amber when no rules configured yet
    statusText = 'Нет активных правил';
  } else if (openCount === totalRules) {
    color = '#10B981'; // Emerald Green (Active / Allowed)
    statusText = 'Активен';
  } else if (openCount > 0) {
    color = '#F59E0B'; // Amber (Partial)
    statusText = `Открыто ${openCount} из ${totalRules}`;
  }

  const autoLaunchEnabled = autoLaunchManager.isEnabled();
  const traySignature = `${color}|${statusText}|${snapshot.currentIp}|${snapshot.firewallElevated}|${autoLaunchEnabled}`;
  if (traySignature === lastTraySignature) {
    return;
  }
  lastTraySignature = traySignature;

  try {
    tray.setImage(createShieldTrayIcon(color));
  } catch {
    // ignore
  }

  if (process.platform === 'darwin') {
    tray.setTitle('');
  }
  tray.setToolTip(`IPShield • ${statusText} (${snapshot.currentIp})`);

  const menuTemplate: Electron.MenuItemConstructorOptions[] = [
    {
      label: statusText,
      enabled: false
    },
    {
      label: `IP: ${snapshot.currentIp}`,
      enabled: false
    },
    { type: 'separator' },
    {
      label: 'Открыть IPShield',
      click: () => {
        void ipMonitor.checkNow(true, true).then(() => runEnforcementCycle());
        showMainWindow();
      }
    },
    {
      label: 'Автозапуск при старте системы',
      type: 'checkbox',
      checked: autoLaunchEnabled,
      click: menuItem => {
        autoLaunchManager.setEnabled(menuItem.checked);
        broadcastSnapshot(true);
      }
    },
    {
      label: 'Проверить обновления',
      click: () => {
        showMainWindow();
        void appUpdater.checkForUpdates(true).then(() => broadcastSnapshot(true));
      }
    }
  ];

  if (snapshot.firewallElevated) {
    menuTemplate.push({
      label: 'Отозвать разрешение',
      click: () => {
        void domainFirewall.revokeElevation().then(() => runEnforcementCycle(true));
      }
    });
  }

  menuTemplate.push(
    { type: 'separator' },
    {
      label: 'Выйти',
      accelerator: process.platform === 'darwin' ? 'Command+Q' : 'Ctrl+Q',
      click: () => {
        void shutdown();
      }
    }
  );

  const contextMenu = Menu.buildFromTemplate(menuTemplate);

  tray.setContextMenu(contextMenu);
}

function getSnapshotSignature(snapshot: RuntimeSnapshot): string {
  return JSON.stringify({
    currentIp: snapshot.currentIp,
    rules: snapshot.rules,
    ips: snapshot.ips,
    ruleStatuses: snapshot.ruleStatuses,
    firewallElevated: snapshot.firewallElevated,
    firewallError: snapshot.firewallError,
    processGuardError: snapshot.processGuardError,
    update: snapshot.update,
    autoLaunch: snapshot.autoLaunch
  });
}

function broadcastSnapshot(force: boolean = false): RuntimeSnapshot {
  const snapshot = buildSnapshot();
  updateTrayAppearance(snapshot);

  const sig = getSnapshotSignature(snapshot);
  if (!force && sig === lastBroadcastSignature) {
    return snapshot;
  }
  lastBroadcastSignature = sig;

  if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isDestroyed()) {
    try {
      if (!mainWindow.webContents.isLoadingMainFrame()) {
        mainWindow.webContents.send('ipshield:snapshot', snapshot);
      }
    } catch {
      // Ignore if renderer frame is not ready yet
    }
  }
  return snapshot;
}

async function runEnforcementCycle(forceBroadcast: boolean = false): Promise<RuntimeSnapshot> {
  const { rules } = store.getState();
  const currentIp = ipMonitor.getCurrentIp();
  const allowedMap = computeAllowedMap(currentIp);

  // Exclude current Electron application and helper processes by PID (S-5)
  const selfPids: number[] = [process.pid];
  try {
    const metrics = app.getAppMetrics();
    for (const m of metrics) {
      if (m.pid > 0) selfPids.push(m.pid);
    }
  } catch {
    // ignore
  }
  processGuard.setIgnoredPids(selfPids);

  cachedFrozenByRule = await processGuard.enforce(rules, allowedMap);
  await domainFirewall.syncDomains(rules, allowedMap);

  return broadcastSnapshot(forceBroadcast);
}

const expectedRendererHref = pathToFileURL(path.join(__dirname, '../renderer/index.html')).href;

function isAuthorizedSender(event: Electron.IpcMainInvokeEvent): boolean {
  const url = (event.senderFrame?.url || '').split(/[?#]/)[0];
  // Strictly compare against the exact file URL of our renderer index.html (S-3)
  return url === expectedRendererHref;
}

function createMainWindow(): void {
  const isMac = process.platform === 'darwin';
  const isWin = process.platform === 'win32';
  const iconPngPath = path.join(__dirname, '../../assets/icon.png');

  mainWindow = new BrowserWindow({
    width: 440,
    height: 600,
    minWidth: 380,
    minHeight: 480,
    show: false,
    title: 'IPShield',
    icon: fs.existsSync(iconPngPath) ? iconPngPath : undefined,
    titleBarStyle: isMac ? 'hiddenInset' : 'default',
    trafficLightPosition: isMac ? { x: 16, y: 18 } : undefined,
    transparent: isMac,
    resizable: true,
    minimizable: true,
    maximizable: true,
    fullscreenable: true,
    closable: true,
    hasShadow: true,
    vibrancy: isMac ? 'under-window' : undefined,
    visualEffectState: isMac ? 'active' : undefined,
    backgroundMaterial: isWin ? 'acrylic' : undefined,
    backgroundColor: isMac ? '#00000000' : '#0d121c',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true
    }
  });

  if (isWin) {
    mainWindow.setMenuBarVisibility(false);
  }

  // Prevent arbitrary navigation away from renderer (S-4)
  mainWindow.webContents.on('will-navigate', event => {
    event.preventDefault();
  });

  // Block opening external windows / popups from renderer (S-4)
  mainWindow.webContents.setWindowOpenHandler(() => {
    return { action: 'deny' };
  });

  const htmlPath = path.join(__dirname, '../renderer/index.html');
  void mainWindow.loadFile(htmlPath);

  // Clicking the native Close button hides the window to Tray instead of stopping protection
  mainWindow.on('close', event => {
    if (!isQuitting && mainWindow) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  const isPackaged = app && typeof app.isPackaged === 'boolean' ? app.isPackaged : false;
  const loginSettings = typeof app.getLoginItemSettings === 'function' ? app.getLoginItemSettings() : null;
  const wasOpenedAtLogin = Boolean(
    loginSettings?.wasOpenedAtLogin || (loginSettings as Record<string, unknown> | null)?.wasOpenedAsHidden
  );
  const isStartedAtLogin = process.argv.includes('--hidden') || (isPackaged && wasOpenedAtLogin);

  mainWindow.once('ready-to-show', () => {
    if (!isStartedAtLogin) {
      showMainWindow();
    }
    broadcastSnapshot();
  });
}

function showMainWindow(): void {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.show();
  mainWindow.focus();
}

function setupIpcHandlers(): void {
  ipcMain.handle('ipshield:getSnapshot', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    return buildSnapshot();
  });

  ipcMain.handle('ipshield:scanApps', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    return scanAvailableApps();
  });

  ipcMain.handle('ipshield:addRule', async (event, ruleInput: Omit<ShieldRule, 'id'>) => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    const { valid, rule } = validateAndSanitizeRule(ruleInput);
    if (valid && rule) {
      store.addRule(rule);
    }
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:updateRule', async (event, rule: ShieldRule) => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    const { valid, rule: cleanRule } = validateAndSanitizeRule(rule);
    if (valid && cleanRule) {
      store.updateRule(cleanRule);
    }
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:removeRule', async (event, ruleId: string) => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    if (typeof ruleId === 'string' && ruleId.trim()) {
      store.removeRule(ruleId.trim());
    }
    return runEnforcementCycle();
  });

  ipcMain.handle(
    'ipshield:addOrUpdateIp',
    async (event, payload: { ip: string; label?: string; ruleIds?: string[] }) => {
      if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
      const { valid, entry } = validateAndSanitizeIpEntry(payload);
      if (valid && entry) {
        store.addOrUpdateIp(entry);
      }
      return runEnforcementCycle();
    }
  );

  ipcMain.handle('ipshield:toggleRuleOnIp', async (event, ip: string, ruleId: string) => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    if (typeof ip === 'string' && typeof ruleId === 'string') {
      store.toggleRuleOnIp(ip, ruleId);
    }
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:removeIp', async (event, ip: string) => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    if (typeof ip === 'string') {
      store.removeIp(ip);
    }
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:refreshIp', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    await ipMonitor.checkNow(true, true);
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:enableFirewallAccess', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    await domainFirewall.requestOneTimeElevation();
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:revokeFirewallAccess', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    await domainFirewall.revokeElevation();
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:checkForUpdates', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    await appUpdater.checkForUpdates(true);
    return broadcastSnapshot(true);
  });

  ipcMain.handle('ipshield:startUpdate', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    void appUpdater.startDownload();
    return broadcastSnapshot(true);
  });

  ipcMain.handle('ipshield:applyUpdate', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    await appUpdater.applyUpdateAndRestart(async () => {
      await cleanupBeforeExit();
    });
    app.quit();
  });

  ipcMain.handle('ipshield:dismissUpdate', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    appUpdater.dismissUpdate();
    return broadcastSnapshot(true);
  });

  ipcMain.handle('ipshield:openReleaseUrl', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    const url = appUpdater.getStatus().releaseUrl;
    if (url && /^https:\/\/github\.com\//i.test(url)) {
      await shell.openExternal(url);
    }
  });

  ipcMain.handle('ipshield:setAutoLaunch', async (event, enabled: boolean) => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    autoLaunchManager.setEnabled(Boolean(enabled));
    return broadcastSnapshot(true);
  });

  ipcMain.handle('ipshield:toggleAutoLaunch', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    autoLaunchManager.toggle();
    return broadcastSnapshot(true);
  });

  ipcMain.handle('ipshield:quitApp', async event => {
    if (!isAuthorizedSender(event)) throw new Error('Unauthorized sender');
    await shutdown();
  });
}

let isShuttingDown = false;
async function cleanupBeforeExit(): Promise<void> {
  if ( isShuttingDown ) return;
  isShuttingDown = true;
  isQuitting = true;

  if (enforceTimer) {
    clearInterval(enforceTimer);
    enforceTimer = null;
  }
  ipMonitor.stop();
  appUpdater.stop();

  try {
    await processGuard.unfreezeAll();
  } catch (err) {
    console.error('[Main] Failed to unfreeze processes on shutdown:', err);
  }

  try {
    await domainFirewall.clearAllBlocks();
  } catch (err) {
    console.error('[Main] Failed to clear hosts blocks on shutdown:', err);
  }
}

async function shutdown(): Promise<void> {
  if (isShuttingDown) return;
  await cleanupBeforeExit();
  app.quit();
}

app.whenReady().then(() => {
  const iconPngPath = path.join(__dirname, '../../assets/icon.png');
  if (process.platform === 'darwin' && app.dock && fs.existsSync(iconPngPath)) {
    try {
      app.dock.setIcon(iconPngPath);
    } catch {
      // ignore
    }
  }

  tray = new Tray(createShieldTrayIcon('#F59E0B'));
  if (process.platform !== 'darwin') {
    tray.on('click', () => {
      showMainWindow();
    });
  }
  autoLaunchManager.init();
  setupIpcHandlers();
  createMainWindow();

  appUpdater.onStatusChange(() => {
    broadcastSnapshot(true);
  });
  appUpdater.start();

  ipMonitor.onIpChange(() => {
    void runEnforcementCycle();
  });
  ipMonitor.start(2500);

  enforceTimer = setInterval(() => {
    void runEnforcementCycle();
  }, 1500);
});

app.on('activate', () => {
  showMainWindow();
});

app.on('before-quit', async event => {
  if (!isQuitting) {
    event.preventDefault();
    await shutdown();
  }
});

app.on('window-all-closed', () => {
  // Keep running in Menu Bar / System Tray
});
