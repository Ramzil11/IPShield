import { contextBridge, ipcRenderer } from 'electron';
import { DetectedAppItem, RuntimeSnapshot, ShieldRule } from '../shared/types';

export interface IpShieldBridge {
  getSnapshot: () => Promise<RuntimeSnapshot>;
  onSnapshotUpdate: (callback: (snapshot: RuntimeSnapshot) => void) => void;
  scanApps: () => Promise<DetectedAppItem[]>;
  addRule: (rule: Omit<ShieldRule, 'id'>) => Promise<RuntimeSnapshot>;
  updateRule: (rule: ShieldRule) => Promise<RuntimeSnapshot>;
  removeRule: (ruleId: string) => Promise<RuntimeSnapshot>;
  addOrUpdateIp: (payload: { ip: string; label?: string; ruleIds?: string[] }) => Promise<RuntimeSnapshot>;
  toggleRuleOnIp: (ip: string, ruleId: string) => Promise<RuntimeSnapshot>;
  removeIp: (ip: string) => Promise<RuntimeSnapshot>;
  refreshIp: () => Promise<RuntimeSnapshot>;
  enableFirewallAccess: () => Promise<RuntimeSnapshot>;
  revokeFirewallAccess: () => Promise<RuntimeSnapshot>;
  checkForUpdates: () => Promise<RuntimeSnapshot>;
  startUpdate: () => Promise<RuntimeSnapshot>;
  applyUpdate: () => Promise<void>;
  dismissUpdate: () => Promise<RuntimeSnapshot>;
  openReleaseUrl: () => Promise<void>;
  quitApp: () => Promise<void>;
}

const api: IpShieldBridge = {
  getSnapshot: () => ipcRenderer.invoke('ipshield:getSnapshot'),
  onSnapshotUpdate: (callback: (snapshot: RuntimeSnapshot) => void) => {
    ipcRenderer.on('ipshield:snapshot', (_event, snapshot: RuntimeSnapshot) => {
      callback(snapshot);
    });
  },
  scanApps: () => ipcRenderer.invoke('ipshield:scanApps'),
  addRule: rule => ipcRenderer.invoke('ipshield:addRule', rule),
  updateRule: rule => ipcRenderer.invoke('ipshield:updateRule', rule),
  removeRule: ruleId => ipcRenderer.invoke('ipshield:removeRule', ruleId),
  addOrUpdateIp: payload => ipcRenderer.invoke('ipshield:addOrUpdateIp', payload),
  toggleRuleOnIp: (ip, ruleId) => ipcRenderer.invoke('ipshield:toggleRuleOnIp', ip, ruleId),
  removeIp: ip => ipcRenderer.invoke('ipshield:removeIp', ip),
  refreshIp: () => ipcRenderer.invoke('ipshield:refreshIp'),
  enableFirewallAccess: () => ipcRenderer.invoke('ipshield:enableFirewallAccess'),
  revokeFirewallAccess: () => ipcRenderer.invoke('ipshield:revokeFirewallAccess'),
  checkForUpdates: () => ipcRenderer.invoke('ipshield:checkForUpdates'),
  startUpdate: () => ipcRenderer.invoke('ipshield:startUpdate'),
  applyUpdate: () => ipcRenderer.invoke('ipshield:applyUpdate'),
  dismissUpdate: () => ipcRenderer.invoke('ipshield:dismissUpdate'),
  openReleaseUrl: () => ipcRenderer.invoke('ipshield:openReleaseUrl'),
  quitApp: () => ipcRenderer.invoke('ipshield:quitApp')
};

contextBridge.exposeInMainWorld('ipshield', api);
