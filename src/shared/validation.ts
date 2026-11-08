import { ShieldRule, AllowedIpEntry, RuleType, PresetKey } from './types';

/**
 * Applies a live IPv4 input mask as the user types:
 * - Strips any non-digit / non-dot characters
 * - Prevents leading dots or consecutive dots
 * - Clamps/blocks octets > 255
 * - Automatically inserts a dot after a 3-digit octet (for the first 3 octets)
 * - Limits total octets to 4
 */
export function applyIpv4Mask(rawInput: string): string {
  const cleaned = rawInput.replace(/[^0-9.]/g, '');
  const rawParts = cleaned.split('.');
  const outOctets: string[] = [];

  for (let i = 0; i < rawParts.length && outOctets.length < 4; i++) {
    const part = rawParts[i];
    if (part === '') {
      if (i > 0 && i === rawParts.length - 1 && outOctets.length > 0 && outOctets.length < 4) {
        return outOctets.join('.') + '.';
      }
      continue;
    }

    let current = '';
    for (const ch of part) {
      const candidate = current + ch;
      const num = Number(candidate);

      if (candidate.length <= 3 && num <= 255) {
        current = candidate;
      } else {
        if (current.length > 0) {
          outOctets.push(current);
          if (outOctets.length >= 4) break;
        }
        current = ch;
      }
    }

    if (current.length > 0 && outOctets.length < 4) {
      outOctets.push(current);
    }
  }

  return outOctets.join('.');
}

export function isValidIpAddress(raw: string): boolean {
  if (typeof raw !== 'string') return false;
  const s = raw.trim();
  const ipv4Regex = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  return ipv4Regex.test(s);
}

export function normalizeAndValidateDomain(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');

  if (!cleaned) return null;

  // Strict check: no newlines, carriage returns, spaces, or tabs (S-2 hosts injection fix)
  if (/[\s\r\n\t]/.test(cleaned)) {
    return null;
  }

  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  if (!domainRegex.test(cleaned)) {
    return null;
  }
  return cleaned;
}

/**
 * Deny-list of critical system binaries to protect against accidental freeze (B-9, R-3).
 */
export const SYSTEM_PROCESS_DENYLIST: ReadonlySet<string> = new Set([
  'launchd',
  'kernel_task',
  'systemd',
  'init',
  'loginwindow',
  'finder',
  'dock',
  'windowserver',
  'controlcenter',
  'systemuiserver',
  'explorer',
  'explorer.exe',
  'terminal',
  'iterm2',
  'iterm',
  'alacritty',
  'warp',
  'bash',
  'zsh',
  'sh',
  'fish',
  'pwsh',
  'powershell',
  'powershell.exe',
  'cmd.exe',
  'taskmgr.exe',
  'services.exe',
  'csrss.exe',
  'lsass.exe',
  'svchost.exe',
  'system'
]);

/**
 * Checks whether a process name or full executable path (`ps -o comm=`) belongs to a protected
 * system binary or shell. Extracts basename and strips leading `-` for login shells (R-3).
 */
export function isDeniedSystemProcess(procName: string): boolean {
  if (typeof procName !== 'string') return true;
  const clean = procName.trim().toLowerCase();
  if (!clean) return true;

  // Extract basename across POSIX (/) and Windows (\) paths, strip leading '-' (e.g. -zsh), and strip .exe
  const base = (clean.split(/[/\\]/).pop() || clean)
    .replace(/^-+/, '')
    .replace(/\.exe$/, '');

  if (!base) return true;

  return (
    SYSTEM_PROCESS_DENYLIST.has(base) ||
    SYSTEM_PROCESS_DENYLIST.has(`${base}.exe`) ||
    SYSTEM_PROCESS_DENYLIST.has(clean)
  );
}

/**
 * Validates that an iconDataUrl is a safe embedded image (`base64` or `;utf8,` SVG)
 * and not an external tracker URL or script payload (S-3, R-1).
 */
export function isSafeDataUrl(url: unknown): boolean {
  if (url === null || url === undefined) return true;
  if (typeof url !== 'string') return false;
  // Maximum length: 1MB to prevent memory exhaustion
  if (url.length === 0 || url.length > 1024 * 1024) return false;

  // 1. Base64-encoded raster or vector image
  if (/^data:image\/(png|jpeg|jpg|webp|svg\+xml|x-icon);base64,[A-Za-z0-9+/=]+$/.test(url)) {
    return true;
  }

  // 2. UTF-8 / URI-encoded SVG image (used by BRAND_ICONS and DEFAULT_DOMAIN_ICON)
  if (/^data:image\/svg\+xml;(utf8|charset=utf-8),/i.test(url)) {
    const rawPayload = url.replace(/^data:image\/svg\+xml;(utf8|charset=utf-8),/i, '');
    let decoded = rawPayload;
    try {
      decoded = decodeURIComponent(rawPayload);
    } catch {
      // keep rawPayload if not percent-encoded
    }
    // Reject script tags, event handlers, javascript: URIs, or external http(s) resources
    if (/<script[\s>]|on[a-z]+\s*=|javascript:/i.test(decoded)) {
      return false;
    }
    const strippedXmlns = decoded
      .replace(/http:\/\/www\.w3\.org\/2000\/svg/gi, '')
      .replace(/http:\/\/www\.w3\.org\/1999\/xlink/gi, '');
    if (/https?:\/\//i.test(strippedXmlns)) {
      return false;
    }
    return true;
  }

  return false;
}

/**
 * Validates and sanitizes a ShieldRule object coming from IPC or file store (S-3, B-5, R-1).
 * Invalid icons are replaced with `null` rather than discarding the entire rule.
 */
export function validateAndSanitizeRule(
  raw: unknown
): { valid: boolean; error?: string; rule?: ShieldRule } {
  if (!raw || typeof raw !== 'object') {
    return { valid: false, error: 'Некорректный объект правила' };
  }

  const obj = raw as Record<string, unknown>;

  const name = typeof obj.name === 'string' ? obj.name.trim().slice(0, 100) : '';
  if (!name) {
    return { valid: false, error: 'Имя правила обязательно' };
  }

  const type: RuleType =
    obj.type === 'app' || obj.type === 'domain' || obj.type === 'preset' ? obj.type : 'app';

  const validPresets: Array<PresetKey> = ['claude', 'codex', 'cursor', 'perplexity', 'gemini', null];
  const presetKey: PresetKey = validPresets.includes(obj.presetKey as PresetKey)
    ? (obj.presetKey as PresetKey)
    : null;

  // R-1 fix: if iconDataUrl is invalid, gracefully fall back to null instead of dropping the rule
  const iconDataUrl: string | null =
    typeof obj.iconDataUrl === 'string' && isSafeDataUrl(obj.iconDataUrl)
      ? obj.iconDataUrl
      : null;

  const appPaths: string[] = Array.isArray(obj.appPaths)
    ? obj.appPaths.filter((p): p is string => typeof p === 'string' && p.trim().length > 0)
    : [];

  const rawProcesses = Array.isArray(obj.processes)
    ? obj.processes.filter((p): p is string => typeof p === 'string' && p.trim().length > 0)
    : [];

  // Filter out any denied system processes (B-9, R-3)
  const processes: string[] = [];
  for (const p of rawProcesses) {
    const trimmed = p.trim().slice(0, 100);
    if (!isDeniedSystemProcess(trimmed)) {
      processes.push(trimmed);
    }
  }

  const domains: string[] = [];
  if (Array.isArray(obj.domains)) {
    for (const d of obj.domains) {
      if (typeof d === 'string') {
        const validated = normalizeAndValidateDomain(d);
        if (validated && !domains.includes(validated)) {
          domains.push(validated);
        }
      }
    }
  }

  const id =
    typeof obj.id === 'string' && obj.id.trim().length > 0
      ? obj.id.trim()
      : `rule-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

  return {
    valid: true,
    rule: {
      id,
      name,
      type,
      presetKey,
      iconDataUrl,
      appPaths,
      processes,
      domains
    }
  };
}

/**
 * Validates and sanitizes an AllowedIpEntry object coming from IPC or file store (S-3, B-5).
 */
export function validateAndSanitizeIpEntry(
  raw: unknown
): { valid: boolean; error?: string; entry?: AllowedIpEntry } {
  if (!raw || typeof raw !== 'object') {
    return { valid: false, error: 'Некорректный объект IP-адреса' };
  }

  const obj = raw as Record<string, unknown>;

  if (typeof obj.ip !== 'string' || !isValidIpAddress(obj.ip)) {
    return { valid: false, error: 'Некорректный IPv4 адрес' };
  }
  const ip = obj.ip.trim();

  const label = typeof obj.label === 'string' ? obj.label.trim().slice(0, 80) : '';

  const ruleIds: string[] = Array.isArray(obj.ruleIds)
    ? obj.ruleIds.filter((id): id is string => typeof id === 'string' && id.trim().length > 0)
    : [];

  return {
    valid: true,
    entry: {
      ip,
      label,
      ruleIds
    }
  };
}
