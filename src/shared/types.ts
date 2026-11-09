export type RuleType = 'app' | 'domain' | 'preset';

export type PresetKey = 'claude' | 'codex' | 'cursor' | 'perplexity' | 'gemini' | null;

export interface ShieldRule {
  id: string;
  name: string;
  type: RuleType;
  presetKey: PresetKey;
  iconDataUrl: string | null;
  appPaths: string[];
  processes: string[];
  domains: string[];
}

export interface AllowedIpEntry {
  ip: string;
  label: string;
  ruleIds: string[];
}

export interface ShieldSettings {
  processGuardEnabled: boolean;
  domainFirewallEnabled: boolean;
  checkIntervalMs: number;
  autoLaunch?: boolean;
}

export interface PersistedState {
  rules: ShieldRule[];
  ips: AllowedIpEntry[];
  settings: ShieldSettings;
}

export interface DetectedAppItem {
  id: string;
  name: string;
  subtitle: string;
  isPreset: boolean;
  presetKey: PresetKey;
  iconDataUrl: string | null;
  appPaths: string[];
  processes: string[];
  domains: string[];
}

export interface RuleRuntimeStatus {
  ruleId: string;
  allowed: boolean;
  frozenPids: number[];
}

export type UpdatePhase = 'idle' | 'checking' | 'available' | 'downloading' | 'ready' | 'error';

export interface UpdateStatusInfo {
  phase: UpdatePhase;
  currentVersion: string;
  latestVersion: string | null;
  releaseUrl: string | null;
  downloadProgress: number;
  dismissed: boolean;
  error: string | null;
}

export interface RuntimeSnapshot {
  currentIp: string;
  ipChecking: boolean;
  lastCheckedAt: number;
  rules: ShieldRule[];
  ips: AllowedIpEntry[];
  ruleStatuses: Record<string, RuleRuntimeStatus>;
  firewallElevated: boolean;
  firewallError: string | null;
  processGuardError: string | null;
  update?: UpdateStatusInfo;
  autoLaunch?: boolean;
}

