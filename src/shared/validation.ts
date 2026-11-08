/**
 * Applies a live IPv4 input mask as the user types:
 * - Strips any non-digit / non-dot characters
 * - Prevents leading dots or consecutive dots
 * - Clamps/blocks octets > 255
 * - Automatically inserts a dot after a 3-digit octet (for the first 3 octets)
 * - Limits total octets to 4
 */
export function applyIpv4Mask(rawInput: string): string {
  // Keep only digits and dots
  const cleaned = rawInput.replace(/[^0-9.]/g, '');
  const rawParts = cleaned.split('.');
  const outOctets: string[] = [];

  for (let i = 0; i < rawParts.length && outOctets.length < 4; i++) {
    const part = rawParts[i];
    if (part === '') {
      // Allow a trailing dot if the user just typed '.' after a valid octet (and we have < 4 octets)
      if (i > 0 && i === rawParts.length - 1 && outOctets.length > 0 && outOctets.length < 4) {
        return outOctets.join('.') + '.';
      }
      continue;
    }

    // Take up to 3 digits; if remaining digits exist (e.g. user typed 4th digit without dot), push overflow to next octet
    let current = '';
    for (const ch of part) {
      const candidate = current + ch;
      const num = Number(candidate);

      if (candidate.length <= 3 && num <= 255) {
        current = candidate;
      } else {
        // Push finished octet and start a new one with `ch`
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
  const s = raw.trim();
  const ipv4Regex = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  return ipv4Regex.test(s);
}

export function normalizeAndValidateDomain(raw: string): string | null {
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');

  if (!cleaned) return null;

  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  if (!domainRegex.test(cleaned)) {
    return null;
  }
  return cleaned;
}

