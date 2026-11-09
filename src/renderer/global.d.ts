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

type UpdatePhase = 'idle' | 'checking' | 'available' | 'downloading' | 'ready' | 'error';

interface UpdateStatusInfo {
  phase: UpdatePhase;
  currentVersion: string;
  latestVersion: string | null;
  releaseUrl: string | null;
  downloadProgress: number;
  dismissed: boolean;
  error: string | null;
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
  processGuardError: string | null;
  update?: UpdateStatusInfo;
  autoLaunch?: boolean;
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
  revokeFirewallAccess: () => Promise<RuntimeSnapshot>;
  checkForUpdates: () => Promise<RuntimeSnapshot>;
  startUpdate: () => Promise<RuntimeSnapshot>;
  applyUpdate: () => Promise<void>;
  dismissUpdate: () => Promise<RuntimeSnapshot>;
  openReleaseUrl: () => Promise<void>;
  setAutoLaunch: (enabled: boolean) => Promise<RuntimeSnapshot>;
  toggleAutoLaunch: () => Promise<RuntimeSnapshot>;
  quitApp: () => Promise<void>;
}

interface Window {
  ipshield: IpShieldBridge;
}

