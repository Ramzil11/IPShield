import fs from 'fs';
import path from 'path';
import { app } from 'electron';
import { AllowedIpEntry, PersistedState, ShieldRule } from '../shared/types';

const DEFAULT_STATE: PersistedState = {
  rules: [],
  ips: [],
  settings: {
    processGuardEnabled: true,
    domainFirewallEnabled: true,
    checkIntervalMs: 3000
  }
};

export class Store {
  private filePath: string;
  private data: PersistedState;

  constructor(customFilePath?: string) {
    if (customFilePath) {
      const dir = path.dirname(customFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      this.filePath = customFilePath;
    } else {
      const userDataPath =
        app && typeof app.getPath === 'function'
          ? app.getPath('userData')
          : path.join(__dirname, '../../.data');
      if (!fs.existsSync(userDataPath)) {
        fs.mkdirSync(userDataPath, { recursive: true });
      }
      this.filePath = path.join(userDataPath, 'ipshield-config.json');
    }
    this.data = this.load();
  }

  private load(): PersistedState {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw) as Partial<PersistedState>;
        return {
          rules: Array.isArray(parsed.rules) ? parsed.rules : [],
          ips: Array.isArray(parsed.ips) ? parsed.ips : [],
          settings: {
            ...DEFAULT_STATE.settings,
            ...(parsed.settings || {})
          }
        };
      }
    } catch (err) {
      console.error('[Store] Failed to load config:', err);
    }
    return JSON.parse(JSON.stringify(DEFAULT_STATE));
  }

  public save(): void {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (err) {
      console.error('[Store] Failed to save config:', err);
    }
  }

  public getState(): PersistedState {
    return this.data;
  }

  public addRule(input: Omit<ShieldRule, 'id'> & { id?: string }): ShieldRule {
    const id = input.id || `rule-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const newRule: ShieldRule = {
      id,
      name: input.name.trim(),
      type: input.type,
      presetKey: input.presetKey || null,
      iconDataUrl: input.iconDataUrl || null,
      appPaths: Array.isArray(input.appPaths) ? input.appPaths : [],
      processes: Array.isArray(input.processes) ? input.processes : [],
      domains: Array.isArray(input.domains) ? input.domains : []
    };
    this.data.rules.push(newRule);
    this.save();
    return newRule;
  }

  public updateRule(updated: ShieldRule): ShieldRule | null {
    const idx = this.data.rules.findIndex(r => r.id === updated.id);
    if (idx === -1) return null;
    const prev = this.data.rules[idx];
    const nextRule: ShieldRule = {
      id: prev.id,
      name: (updated.name || '').trim() || prev.name,
      type: updated.type || prev.type,
      presetKey: updated.presetKey !== undefined ? updated.presetKey : prev.presetKey,
      iconDataUrl: updated.iconDataUrl || prev.iconDataUrl,
      appPaths: Array.isArray(updated.appPaths) ? updated.appPaths : [],
      processes: Array.isArray(updated.processes) ? updated.processes : [],
      domains: Array.isArray(updated.domains) ? updated.domains : []
    };
    this.data.rules[idx] = nextRule;
    this.save();
    return nextRule;
  }

  public removeRule(ruleId: string): void {
    this.data.rules = this.data.rules.filter(r => r.id !== ruleId);
    this.data.ips = this.data.ips.map(entry => ({
      ...entry,
      ruleIds: entry.ruleIds.filter(id => id !== ruleId)
    }));
    this.save();
  }

  public addOrUpdateIp(payload: { ip: string; label?: string; ruleIds?: string[] }): AllowedIpEntry[] {
    const cleanIp = (payload.ip || '').trim();
    if (!cleanIp) return this.data.ips;

    const existing = this.data.ips.find(item => item.ip === cleanIp);
    if (existing) {
      if (payload.label && payload.label.trim()) {
        existing.label = payload.label.trim();
      }
      if (Array.isArray(payload.ruleIds)) {
        existing.ruleIds = Array.from(new Set([...existing.ruleIds, ...payload.ruleIds]));
      }
    } else {
      this.data.ips.unshift({
        ip: cleanIp,
        label: (payload.label || 'VPN').trim(),
        ruleIds: Array.isArray(payload.ruleIds)
          ? Array.from(new Set(payload.ruleIds))
          : this.data.rules.map(r => r.id)
      });
    }
    this.save();
    return this.data.ips;
  }

  public toggleRuleOnIp(ip: string, ruleId: string): AllowedIpEntry[] {
    const entry = this.data.ips.find(item => item.ip === ip);
    if (!entry) return this.data.ips;
    if (entry.ruleIds.includes(ruleId)) {
      entry.ruleIds = entry.ruleIds.filter(id => id !== ruleId);
    } else {
      entry.ruleIds.push(ruleId);
    }
    this.save();
    return this.data.ips;
  }

  public removeIp(ip: string): AllowedIpEntry[] {
    this.data.ips = this.data.ips.filter(item => item.ip !== ip);
    this.save();
    return this.data.ips;
  }
}

