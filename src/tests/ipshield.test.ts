import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn, execFileSync } from 'child_process';
import {
  applyIpv4Mask,
  isValidIpAddress,
  normalizeAndValidateDomain
} from '../shared/validation';
import { Store } from '../main/store';
import { DomainFirewall } from '../main/domainFirewall';
import { ProcessGuard } from '../main/processGuard';
import { ShieldRule } from '../shared/types';

describe('IPShield Test Suite (Vitest)', () => {
  it('1. IPv4 Input Mask & IP Validation', () => {
    // Strips letters and invalid characters in real time
    expect(applyIpv4Mask('abc185.212.xyz44.19!@#')).toBe('185.212.44.19');

    // Automatically splits octets > 255 or > 3 digits into next octet
    expect(applyIpv4Mask('19216811')).toBe('192.168.11');
    expect(applyIpv4Mask('999')).toBe('99.9');

    // Limits to 4 octets maximum
    expect(applyIpv4Mask('10.20.30.40.50.60')).toBe('10.20.30.40');

    // Preserves trailing dot while user is typing next octet
    expect(applyIpv4Mask('185.')).toBe('185.');

    // Strict IPv4 validation
    expect(isValidIpAddress('185.212.44.19')).toBe(true);
    expect(isValidIpAddress('0.0.0.0')).toBe(true);
    expect(isValidIpAddress('255.255.255.255')).toBe(true);
    expect(isValidIpAddress('256.1.1.1')).toBe(false);
    expect(isValidIpAddress('185.212.44')).toBe(false);
    expect(isValidIpAddress('randomword')).toBe(false);
    expect(isValidIpAddress('')).toBe(false);
  });

  it('2. Domain Normalization & Validation', () => {
    expect(normalizeAndValidateDomain('claude.ai')).toBe('claude.ai');
    expect(
      normalizeAndValidateDomain('https://api.anthropic.com:443/v1/messages')
    ).toBe('api.anthropic.com');
    expect(normalizeAndValidateDomain('  CHATGPT.COM/c/123 ')).toBe('chatgpt.com');

    // Rejects random words without TLD or invalid characters
    expect(normalizeAndValidateDomain('randomword')).toBeNull();
    expect(normalizeAndValidateDomain('12345')).toBeNull();
    expect(normalizeAndValidateDomain('https://')).toBeNull();
    expect(normalizeAndValidateDomain('-bad.com')).toBeNull();
  });

  it('3. Store & Per-Rule Static IP Binding Matrix', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-store-test-'));
    const configFile = path.join(tmpDir, 'config.json');
    const store = new Store(configFile);

    // Starts completely clean (no undeletable hardcoded rules)
    expect(store.getState().rules).toHaveLength(0);

    // Add Claude and Codex rules
    const claudeRule = store.addRule({
      name: 'Claude',
      type: 'preset',
      presetKey: 'claude',
      iconDataUrl: null,
      appPaths: ['/Applications/Claude.app'],
      processes: ['Claude', 'claude'],
      domains: ['claude.ai', 'api.anthropic.com']
    });

    const codexRule = store.addRule({
      name: 'Codex',
      type: 'preset',
      presetKey: 'codex',
      iconDataUrl: null,
      appPaths: [],
      processes: ['codex'],
      domains: ['chatgpt.com', 'api.openai.com']
    });

    // Bind 185.212.44.19 ONLY to Claude, and 45.132.10.88 ONLY to Codex
    store.addOrUpdateIp({
      ip: '185.212.44.19',
      label: 'VPN #1 (Claude)',
      ruleIds: [claudeRule.id]
    });
    store.addOrUpdateIp({
      ip: '45.132.10.88',
      label: 'VPN #2 (Codex)',
      ruleIds: [codexRule.id]
    });

    const checkAllowed = (currentIp: string, ruleId: string): boolean => {
      const entry = store.getState().ips.find(i => i.ip === currentIp);
      return Boolean(entry && entry.ruleIds.includes(ruleId));
    };

    // Case A: Untrusted IP (91.64.17.203) -> Both BLOCKED
    expect(checkAllowed('91.64.17.203', claudeRule.id)).toBe(false);
    expect(checkAllowed('91.64.17.203', codexRule.id)).toBe(false);

    // Case B: Connected to VPN #1 (185.212.44.19) -> Claude ALLOWED, Codex BLOCKED
    expect(checkAllowed('185.212.44.19', claudeRule.id)).toBe(true);
    expect(checkAllowed('185.212.44.19', codexRule.id)).toBe(false);

    // Case C: Connected to VPN #2 (45.132.10.88) -> Claude BLOCKED, Codex ALLOWED
    expect(checkAllowed('45.132.10.88', claudeRule.id)).toBe(false);
    expect(checkAllowed('45.132.10.88', codexRule.id)).toBe(true);

    // Toggle Codex onto VPN #1 -> Now both allowed on 185.212.44.19
    store.toggleRuleOnIp('185.212.44.19', codexRule.id);
    expect(checkAllowed('185.212.44.19', codexRule.id)).toBe(true);

    // Delete Claude rule -> cleanly removed from rules and IP bindings
    store.removeRule(claudeRule.id);
    expect(store.getState().rules).toHaveLength(1);
    expect(store.getState().ips[1].ruleIds.includes(claudeRule.id)).toBe(false);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('4. DomainFirewall Selective Domain Blocking & Cleanup', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-hosts-test-'));
    const mockHosts = path.join(tmpDir, 'hosts');
    const originalHostsContent = '127.0.0.1 localhost\n::1 localhost\n';
    fs.writeFileSync(mockHosts, originalHostsContent, 'utf-8');

    const firewall = new DomainFirewall(mockHosts, true);

    const rules: ShieldRule[] = [
      {
        id: 'r-claude',
        name: 'Claude',
        type: 'preset',
        presetKey: 'claude',
        iconDataUrl: null,
        appPaths: [],
        processes: [],
        domains: ['claude.ai', 'api.anthropic.com']
      },
      {
        id: 'r-codex',
        name: 'Codex',
        type: 'preset',
        presetKey: 'codex',
        iconDataUrl: null,
        appPaths: [],
        processes: [],
        domains: ['chatgpt.com', 'api.openai.com']
      }
    ];

    // Scenario 1: Claude is BLOCKED (allowed=false), Codex is ALLOWED (allowed=true)
    await firewall.syncDomains(rules, { 'r-claude': false, 'r-codex': true });
    const contentWhenClaudeBlocked = fs.readFileSync(mockHosts, 'utf-8');

    expect(contentWhenClaudeBlocked).toContain('127.0.0.1 localhost');
    expect(contentWhenClaudeBlocked).toContain('0.0.0.0 claude.ai');
    expect(contentWhenClaudeBlocked).toContain(':: claude.ai');
    expect(contentWhenClaudeBlocked).toContain('0.0.0.0 www.claude.ai');
    expect(contentWhenClaudeBlocked).toContain('0.0.0.0 api.anthropic.com');
    // Codex domains MUST NOT be blocked because Codex is allowed on current IP!
    expect(contentWhenClaudeBlocked).not.toContain('chatgpt.com');
    expect(contentWhenClaudeBlocked).not.toContain('api.openai.com');

    // Scenario 2: Both rules are ALLOWED (VPN matches both) -> hosts block removed
    await firewall.syncDomains(rules, { 'r-claude': true, 'r-codex': true });
    const contentWhenAllAllowed = fs.readFileSync(mockHosts, 'utf-8');
    expect(contentWhenAllAllowed).not.toContain('claude.ai');
    expect(contentWhenAllAllowed).toContain('127.0.0.1 localhost');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('5. ProcessGuard Real OS Process Freezing (SIGSTOP) & Resuming (SIGCONT)', async () => {
    const guard = new ProcessGuard();

    // Spawn a real dummy process simulating Claude Code CLI (@anthropic-ai/claude-code)
    const dummyChild = spawn(
      process.execPath,
      ['-e', 'setInterval(() => {}, 500)', '@anthropic-ai/claude-code/cli.js'],
      { stdio: 'ignore' }
    );

    const pid = dummyChild.pid as number;
    expect(pid).toBeGreaterThan(0);

    try {
      const rules: ShieldRule[] = [
        {
          id: 'rule-mock-cli',
          name: 'Mock Claude CLI',
          type: 'app',
          presetKey: null,
          iconDataUrl: null,
          appPaths: [],
          processes: ['@anthropic-ai/claude-code'],
          domains: []
        }
      ];

      // 1. Enforce BLOCKED state (IP does not match) -> process must be frozen
      const frozenMapBlocked = await guard.enforce(rules, { 'rule-mock-cli': false });
      expect(frozenMapBlocked['rule-mock-cli']).toContain(pid);

      if (process.platform === 'darwin') {
        const stateStr = execFileSync('ps', ['-o', 'state=', '-p', String(pid)], {
          encoding: 'utf-8'
        }).trim();
        expect(stateStr.startsWith('T')).toBe(true);
      }

      // 2. Enforce ALLOWED state (IP matches static VPN IP) -> process must be resumed
      const frozenMapAllowed = await guard.enforce(rules, { 'rule-mock-cli': true });
      expect(frozenMapAllowed['rule-mock-cli'] || []).toHaveLength(0);

      if (process.platform === 'darwin') {
        const stateAfter = execFileSync('ps', ['-o', 'state=', '-p', String(pid)], {
          encoding: 'utf-8'
        }).trim();
        expect(stateAfter.startsWith('T')).toBe(false);
      }
    } finally {
      await guard.unfreezeAll();
      dummyChild.kill('SIGKILL');
    }
  });

  it('6. Editable Templates & Combined Processes/Domains Update', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-edit-test-'));
    const configFile = path.join(tmpDir, 'config.json');
    const store = new Store(configFile);

    const claudeRule = store.addRule({
      name: 'Claude',
      type: 'preset',
      presetKey: 'claude',
      iconDataUrl: null,
      appPaths: ['/Applications/Claude.app'],
      processes: ['Claude', 'Claude.exe', 'claude', '@anthropic-ai/claude-code'],
      domains: ['claude.ai', 'api.anthropic.com']
    });

    // User removes 'Claude.exe' and adds a custom process 'claude-beta' and a new domain 'beta.anthropic.com'
    const updated = store.updateRule({
      ...claudeRule,
      processes: ['Claude', 'claude', '@anthropic-ai/claude-code', 'claude-beta'],
      domains: ['claude.ai', 'api.anthropic.com', 'beta.anthropic.com']
    });

    expect(updated).not.toBeNull();
    expect(updated?.processes).not.toContain('Claude.exe');
    expect(updated?.processes).toContain('claude-beta');
    expect(updated?.domains).toContain('beta.anthropic.com');

    // Verify persisted state on disk
    const reloaded = new Store(configFile);
    expect(reloaded.getState().rules[0].processes).toEqual([
      'Claude',
      'claude',
      '@anthropic-ai/claude-code',
      'claude-beta'
    ]);
    expect(reloaded.getState().rules[0].domains).toEqual([
      'claude.ai',
      'api.anthropic.com',
      'beta.anthropic.com'
    ]);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
