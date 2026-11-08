type RuleType = 'app' | 'domain' | 'preset';
type PresetKey = 'claude' | 'codex' | 'cursor' | 'perplexity' | 'gemini' | null;

interface ShieldRule {
  id: string;
  name: string;
  type: RuleType;
  presetKey: PresetKey;
  iconDataUrl: string | null;
  appPaths: string[];
  processes: string[];
  domains: string[];
}

interface AllowedIpEntry {
  ip: string;
  label: string;
  ruleIds: string[];
}

interface DetectedAppItem {
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

interface RuleRuntimeStatus {
  ruleId: string;
  allowed: boolean;
  frozenPids: number[];
}

interface RuntimeSnapshot {
  currentIp: string;
  ipChecking: boolean;
  lastCheckedAt: number;
  rules: ShieldRule[];
  ips: AllowedIpEntry[];
  ruleStatuses: Record<string, RuleRuntimeStatus>;
  firewallElevated: boolean;
  firewallError: string | null;
}

interface IpShieldBridge {
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
  quitApp: () => Promise<void>;
}

interface Window {
  ipshield: IpShieldBridge;
}

