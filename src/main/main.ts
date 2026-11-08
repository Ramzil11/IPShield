import path from 'path';
import fs from 'fs';
import { app, BrowserWindow, ipcMain, Menu, nativeImage, Tray } from 'electron';
import { Store } from './store';
import { IpMonitor } from './ipMonitor';
import { ProcessGuard } from './processGuard';
import { DomainFirewall } from './domainFirewall';
import { scanAvailableApps } from './appScanner';
import { RuleRuntimeStatus, RuntimeSnapshot, ShieldRule } from '../shared/types';

if (app && typeof app.setName === 'function') {
  app.setName('IPShield');
}

let tray: Tray | null = null;
let mainWindow: BrowserWindow | null = null;
let isQuitting = false;

const store = new Store();
const ipMonitor = new IpMonitor();
const processGuard = new ProcessGuard();
const domainFirewall = new DomainFirewall();

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
    firewallError: domainFirewall.getLastError()
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

  const traySignature = `${color}|${statusText}|${snapshot.currentIp}`;
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

  const contextMenu = Menu.buildFromTemplate([
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
        void ipMonitor.checkNow().then(() => runEnforcementCycle());
        showMainWindow();
      }
    },
    { type: 'separator' },
    {
      label: 'Выйти',
      accelerator: process.platform === 'darwin' ? 'Command+Q' : 'Ctrl+Q',
      click: async () => {
        isQuitting = true;
        await processGuard.unfreezeAll();
        await domainFirewall.clearAllBlocks();
        app.quit();
      }
    }
  ]);

  tray.setContextMenu(contextMenu);
}

function getSnapshotSignature(snapshot: RuntimeSnapshot): string {
  return JSON.stringify({
    currentIp: snapshot.currentIp,
    rules: snapshot.rules,
    ips: snapshot.ips,
    ruleStatuses: snapshot.ruleStatuses,
    firewallElevated: snapshot.firewallElevated,
    firewallError: snapshot.firewallError
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

  cachedFrozenByRule = await processGuard.enforce(rules, allowedMap);
  await domainFirewall.syncDomains(rules, allowedMap);

  return broadcastSnapshot(forceBroadcast);
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
      nodeIntegration: false
    }
  });

  if (isWin) {
    mainWindow.setMenuBarVisibility(false);
  }

  const htmlPath = path.join(__dirname, '../renderer/index.html');
  void mainWindow.loadFile(htmlPath);

  // Clicking the native Close button hides the window to Tray instead of stopping protection
  mainWindow.on('close', event => {
    if (!isQuitting && mainWindow) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.once('ready-to-show', () => {
    showMainWindow();
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
  ipcMain.handle('ipshield:getSnapshot', async () => {
    return buildSnapshot();
  });

  ipcMain.handle('ipshield:scanApps', async () => {
    return scanAvailableApps();
  });

  ipcMain.handle('ipshield:addRule', async (_event, ruleInput: Omit<ShieldRule, 'id'>) => {
    store.addRule(ruleInput);
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:updateRule', async (_event, rule: ShieldRule) => {
    store.updateRule(rule);
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:removeRule', async (_event, ruleId: string) => {
    store.removeRule(ruleId);
    return runEnforcementCycle();
  });

  ipcMain.handle(
    'ipshield:addOrUpdateIp',
    async (_event, payload: { ip: string; label?: string; ruleIds?: string[] }) => {
      store.addOrUpdateIp(payload);
      return runEnforcementCycle();
    }
  );

  ipcMain.handle('ipshield:toggleRuleOnIp', async (_event, ip: string, ruleId: string) => {
    store.toggleRuleOnIp(ip, ruleId);
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:removeIp', async (_event, ip: string) => {
    store.removeIp(ip);
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:refreshIp', async () => {
    await ipMonitor.checkNow();
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:enableFirewallAccess', async () => {
    await domainFirewall.requestOneTimeElevation();
    return runEnforcementCycle();
  });

  ipcMain.handle('ipshield:quitApp', async () => {
    isQuitting = true;
    await processGuard.unfreezeAll();
    await domainFirewall.clearAllBlocks();
    app.quit();
  });
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
  setupIpcHandlers();
  createMainWindow();

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
    isQuitting = true;
    if (enforceTimer) clearInterval(enforceTimer);
    ipMonitor.stop();
    await processGuard.unfreezeAll();
    await domainFirewall.clearAllBlocks();
    app.quit();
  }
});

app.on('window-all-closed', () => {
  // Keep running in Menu Bar / System Tray
});
