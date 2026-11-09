import fs from 'fs';
import path from 'path';
import { app } from 'electron';
import { AllowedIpEntry, PersistedState, ShieldRule, ShieldSettings } from '../shared/types';
import { BRAND_ICONS } from '../shared/brandIcons';
import {
  validateAndSanitizeRule,
  validateAndSanitizeIpEntry
} from '../shared/validation';

export function getDefaultRules(): ShieldRule[] {
  return [
    {
      id: 'default-claude',
      name: 'Claude',
      type: 'preset',
      presetKey: 'claude',
      iconDataUrl: BRAND_ICONS.claude,
      appPaths: process.platform === 'darwin' ? ['/Applications/Claude.app'] : [],
      processes: ['Claude', 'Claude.exe', 'claude', '@anthropic-ai/claude-code'],
      domains: [
        'claude.ai',
        'www.claude.ai',
        'anthropic.com',
        'www.anthropic.com',
        'api.anthropic.com',
        'console.anthropic.com',
        'statsig.anthropic.com'
      ]
    },
    {
      id: 'default-codex',
      name: 'Codex & ChatGPT',
      type: 'preset',
      presetKey: 'codex',
      iconDataUrl: BRAND_ICONS.codex,
      appPaths:
        process.platform === 'darwin'
          ? ['/Applications/ChatGPT.app', '/Applications/Codex.app']
          : [],
      processes: ['codex', '@openai/codex', 'ChatGPT', 'ChatGPT.exe'],
      domains: [
        'chatgpt.com',
        'www.chatgpt.com',
        'openai.com',
        'www.openai.com',
        'api.openai.com',
        'platform.openai.com',
        'auth.openai.com'
      ]
    }
  ];
}

const DEFAULT_STATE: PersistedState = {
  rules: [],
  ips: [],
  settings: {
    processGuardEnabled: true,
    domainFirewallEnabled: true,
    checkIntervalMs: 3000,
    autoLaunch: true
  }
};

export class Store {
  private filePath: string;
  private data: PersistedState;

  constructor(customFilePath?: string, populateDefaults: boolean = true) {
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
    this.data = this.load(populateDefaults);
  }

  private load(populateDefaults: boolean = true): PersistedState {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw) as Partial<PersistedState>;

        const validRules: ShieldRule[] = [];
        if (Array.isArray(parsed.rules)) {
          for (const item of parsed.rules) {
            const { valid, rule } = validateAndSanitizeRule(item);
            if (valid && rule) {
              validRules.push(rule);
            }
          }
        }

        const validIps: AllowedIpEntry[] = [];
        if (Array.isArray(parsed.ips)) {
          for (const item of parsed.ips) {
            const { valid, entry } = validateAndSanitizeIpEntry(item);
            if (valid && entry) {
              validIps.push(entry);
            }
          }
        }

        return {
          rules: validRules,
          ips: validIps,
          settings: {
            ...DEFAULT_STATE.settings,
            ...(parsed.settings || {})
          }
        };
      }
    } catch (err) {
      console.error('[Store] Failed to load config, resetting to safe defaults:', err);
    }
    
    const initialRules = populateDefaults ? getDefaultRules() : [];
    const initialState: PersistedState = {
      rules: initialRules,
      ips: [],
      settings: { ...DEFAULT_STATE.settings }
    };
    this.data = initialState;
    this.save();
    return initialState;
  }

  public save(): void {
    const tmpPath = `${this.filePath}.tmp`;
    try {
      const json = JSON.stringify(this.data, null, 2);
      fs.writeFileSync(tmpPath, json, 'utf-8');
      fs.renameSync(tmpPath, this.filePath);
    } catch (err) {
      try {
        if (fs.existsSync(tmpPath)) {
          fs.unlinkSync(tmpPath);
        }
      } catch {
        // ignore
      }
      try {
        fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf-8');
      } catch (fallbackErr) {
        console.error('[Store] Failed to save config:', fallbackErr);
      }
    }
  }

  /**
   * Returns a structural clone of the current persisted state without expensive JSON serialization (Q-6).
   */
  public getState(): PersistedState {
    return {
      rules: this.data.rules.map(r => ({
        ...r,
        appPaths: [...r.appPaths],
        processes: [...r.processes],
        domains: [...r.domains]
      })),
      ips: this.data.ips.map(i => ({
        ...i,
        ruleIds: [...i.ruleIds]
      })),
      settings: { ...this.data.settings }
    };
  }

  public addRule(input: Omit<ShieldRule, 'id'> & { id?: string }): ShieldRule {
    const { valid, rule, error } = validateAndSanitizeRule(input);
    if (!valid || !rule) {
      throw new Error(error || 'Некорректные параметры правила');
    }

    this.data.rules.push(rule);
    this.save();
    return rule;
  }

  public updateRule(updated: ShieldRule): ShieldRule | null {
    const idx = this.data.rules.findIndex(r => r.id === updated.id);
    if (idx === -1) return null;

    const { valid, rule, error } = validateAndSanitizeRule(updated);
    if (!valid || !rule) {
      throw new Error(error || 'Некорректные параметры обновления правила');
    }

    this.data.rules[idx] = rule;
    this.save();
    return rule;
  }

  public removeRule(ruleId: string): void {
    if (typeof ruleId !== 'string') return;
    this.data.rules = this.data.rules.filter(r => r.id !== ruleId);
    this.data.ips = this.data.ips.map(entry => ({
      ...entry,
      ruleIds: entry.ruleIds.filter(id => id !== ruleId)
    }));
    this.save();
  }

  public addOrUpdateIp(payload: { ip: string; label?: string; ruleIds?: string[] }): AllowedIpEntry[] {
    const { valid, entry, error } = validateAndSanitizeIpEntry(payload);
    if (!valid || !entry) {
      throw new Error(error || 'Некорректный IP-адрес');
    }

    const existing = this.data.ips.find(item => item.ip === entry.ip);
    if (existing) {
      if (entry.label) {
        existing.label = entry.label;
      }
      if (Array.isArray(entry.ruleIds) && entry.ruleIds.length > 0) {
        existing.ruleIds = Array.from(new Set([...existing.ruleIds, ...entry.ruleIds]));
      }
    } else {
      this.data.ips.unshift({
        ip: entry.ip,
        label: entry.label || 'VPN',
        ruleIds: entry.ruleIds.length > 0 ? entry.ruleIds : this.data.rules.map(r => r.id)
      });
    }
    this.save();
    return this.getState().ips;
  }

  public toggleRuleOnIp(ip: string, ruleId: string): AllowedIpEntry[] {
    if (typeof ip !== 'string' || typeof ruleId !== 'string') return this.getState().ips;
    const entry = this.data.ips.find(item => item.ip === ip.trim());
    if (!entry) return this.getState().ips;

    if (entry.ruleIds.includes(ruleId)) {
      entry.ruleIds = entry.ruleIds.filter(id => id !== ruleId);
    } else {
      entry.ruleIds.push(ruleId);
    }
    this.save();
    return this.getState().ips;
  }

  public removeIp(ip: string): AllowedIpEntry[] {
    if (typeof ip !== 'string') return this.getState().ips;
    this.data.ips = this.data.ips.filter(item => item.ip !== ip.trim());
    this.save();
    return this.getState().ips;
  }

  public updateSettings(partial: Partial<ShieldSettings>): ShieldSettings {
    this.data.settings = {
      ...this.data.settings,
      ...partial
    };
    this.save();
    return { ...this.data.settings };
  }
}
