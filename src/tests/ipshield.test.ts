import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import {
  applyIpv4Mask,
  isValidIpAddress,
  normalizeAndValidateDomain,
  isSafeDataUrl,
  isDeniedSystemProcess,
  validateAndSanitizeRule
} from '../shared/validation';
import { BRAND_ICONS } from '../shared/brandIcons';
import { Store } from '../main/store';
import { DomainFirewall } from '../main/domainFirewall';
import { ProcessGuard } from '../main/processGuard';
import { IpMonitor } from '../main/ipMonitor';
import { ShieldRule } from '../shared/types';

describe('IPShield Test Suite (Vitest)', () => {
  it('1. IPv4 Input Mask & IP Validation', () => {
    expect(applyIpv4Mask('abc185.212.xyz44.19!@#')).toBe('185.212.44.19');
    expect(applyIpv4Mask('19216811')).toBe('192.168.11');
    expect(applyIpv4Mask('999')).toBe('99.9');
    expect(applyIpv4Mask('10.20.30.40.50.60')).toBe('10.20.30.40');
    expect(applyIpv4Mask('185.')).toBe('185.');

    expect(isValidIpAddress('185.212.44.19')).toBe(true);
    expect(isValidIpAddress('0.0.0.0')).toBe(true);
    expect(isValidIpAddress('255.255.255.255')).toBe(true);
    expect(isValidIpAddress('256.1.1.1')).toBe(false);
    expect(isValidIpAddress('185.212.44')).toBe(false);
    expect(isValidIpAddress('randomword')).toBe(false);
    expect(isValidIpAddress('')).toBe(false);
  });

  it('2. Domain Normalization & Validation (Injection Prevention S-2)', () => {
    expect(normalizeAndValidateDomain('claude.ai')).toBe('claude.ai');
    expect(
      normalizeAndValidateDomain('https://api.anthropic.com:443/v1/messages')
    ).toBe('api.anthropic.com');
    expect(normalizeAndValidateDomain('  CHATGPT.COM/c/123 ')).toBe('chatgpt.com');

    expect(normalizeAndValidateDomain('randomword')).toBeNull();
    expect(normalizeAndValidateDomain('12345')).toBeNull();
    expect(normalizeAndValidateDomain('https://')).toBeNull();
    expect(normalizeAndValidateDomain('-bad.com')).toBeNull();

    // Security S-2: Rejects newlines, carriage returns, spaces, or embedded IP records
    expect(normalizeAndValidateDomain('x.com\n6.6.6.6 bank.ru')).toBeNull();
    expect(normalizeAndValidateDomain('evil.com\r\n1.1.1.1 test.com')).toBeNull();
    expect(normalizeAndValidateDomain('example.com 127.0.0.1')).toBeNull();
  });

  it('3. Store & Per-Rule Static IP Binding Matrix + Corruption Resilience (B-5)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-store-test-'));
    const configFile = path.join(tmpDir, 'config.json');
    const store = new Store(configFile);

    expect(store.getState().rules).toHaveLength(0);

    const claudeRule = store.addRule({
      name: 'Claude',
      type: 'preset',
      presetKey: 'claude',
      iconDataUrl: BRAND_ICONS.claude,
      appPaths: ['/Applications/Claude.app'],
      processes: ['Claude', 'claude'],
      domains: ['claude.ai', 'api.anthropic.com']
    });

    const codexRule = store.addRule({
      name: 'Codex',
      type: 'preset',
      presetKey: 'codex',
      iconDataUrl: BRAND_ICONS.codex,
      appPaths: [],
      processes: ['codex'],
      domains: ['chatgpt.com', 'api.openai.com']
    });

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

    expect(checkAllowed('91.64.17.203', claudeRule.id)).toBe(false);
    expect(checkAllowed('91.64.17.203', codexRule.id)).toBe(false);

    expect(checkAllowed('185.212.44.19', claudeRule.id)).toBe(true);
    expect(checkAllowed('185.212.44.19', codexRule.id)).toBe(false);

    expect(checkAllowed('45.132.10.88', claudeRule.id)).toBe(false);
    expect(checkAllowed('45.132.10.88', codexRule.id)).toBe(true);

    store.toggleRuleOnIp('185.212.44.19', codexRule.id);
    expect(checkAllowed('185.212.44.19', codexRule.id)).toBe(true);

    store.removeRule(claudeRule.id);
    expect(store.getState().rules).toHaveLength(1);
    expect(store.getState().ips[1].ruleIds.includes(claudeRule.id)).toBe(false);

    // Test B-5: Corrupted JSON recovery
    fs.writeFileSync(configFile, '{"rules": "corrupted", "ips": null}', 'utf-8');
    const recoveredStore = new Store(configFile);
    expect(recoveredStore.getState().rules).toEqual([]);
    expect(recoveredStore.getState().ips).toEqual([]);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('4. DomainFirewall Selective Domain Blocking & Cleanup + Backup Verification (B-6)', async () => {
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
        iconDataUrl: BRAND_ICONS.claude,
        appPaths: [],
        processes: [],
        domains: ['claude.ai', 'api.anthropic.com']
      },
      {
        id: 'r-codex',
        name: 'Codex',
        type: 'preset',
        presetKey: 'codex',
        iconDataUrl: BRAND_ICONS.codex,
        appPaths: [],
        processes: [],
        domains: ['chatgpt.com', 'api.openai.com']
      }
    ];

    await firewall.syncDomains(rules, { 'r-claude': false, 'r-codex': true });
    const contentWhenClaudeBlocked = fs.readFileSync(mockHosts, 'utf-8');

    expect(contentWhenClaudeBlocked).toContain('127.0.0.1 localhost');
    expect(contentWhenClaudeBlocked).toContain('0.0.0.0 claude.ai');
    expect(contentWhenClaudeBlocked).toContain(':: claude.ai');
    expect(contentWhenClaudeBlocked).toContain('0.0.0.0 www.claude.ai');
    expect(contentWhenClaudeBlocked).toContain('0.0.0.0 api.anthropic.com');
    expect(contentWhenClaudeBlocked).not.toContain('chatgpt.com');
    expect(fs.existsSync(`${mockHosts}.backup`)).toBe(true);

    await firewall.syncDomains(rules, { 'r-claude': true, 'r-codex': true });
    const contentWhenAllAllowed = fs.readFileSync(mockHosts, 'utf-8');
    expect(contentWhenAllAllowed).not.toContain('claude.ai');
    expect(contentWhenAllAllowed).toContain('127.0.0.1 localhost');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('5. ProcessGuard Process Freezing (SIGSTOP) & Resuming (SIGCONT) with Dependency Injection', async () => {
    const dummyChild = spawn(
      process.execPath,
      ['-e', 'setInterval(() => {}, 500)'],
      { stdio: 'ignore' }
    );

    const pid = dummyChild.pid as number;
    expect(pid).toBeGreaterThan(0);

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-proc-test-'));
    const recoveryFile = path.join(tmpDir, 'frozen-recovery.json');

    const guard = new ProcessGuard({
      recoveryFilePath: recoveryFile,
      customProcessLister: async () => [
        {
          pid,
          ppid: process.pid,
          comm: 'dummy-target-app',
          args: 'dummy-target-app --worker'
        }
      ]
    });

    try {
      const rules: ShieldRule[] = [
        {
          id: 'rule-mock-cli',
          name: 'Mock Target App',
          type: 'app',
          presetKey: null,
          iconDataUrl: null,
          appPaths: [],
          processes: ['dummy-target-app'],
          domains: []
        }
      ];

      const frozenMapBlocked = await guard.enforce(rules, { 'rule-mock-cli': false });
      expect(frozenMapBlocked['rule-mock-cli']).toContain(pid);
      expect(fs.existsSync(recoveryFile)).toBe(true);

      const frozenMapAllowed = await guard.enforce(rules, { 'rule-mock-cli': true });
      expect(frozenMapAllowed['rule-mock-cli'] || []).toHaveLength(0);
      expect(fs.existsSync(recoveryFile)).toBe(false);
    } finally {
      await guard.unfreezeAll();
      dummyChild.kill('SIGKILL');
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('6. Editable Templates & Combined Processes/Domains Update + Brand Icon Persistence (R-1)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-edit-test-'));
    const configFile = path.join(tmpDir, 'config.json');
    const store = new Store(configFile);

    const claudeRule = store.addRule({
      name: 'Claude',
      type: 'preset',
      presetKey: 'claude',
      iconDataUrl: BRAND_ICONS.claude,
      appPaths: ['/Applications/Claude.app'],
      processes: ['Claude', 'Claude.exe', 'claude', '@anthropic-ai/claude-code'],
      domains: ['claude.ai', 'api.anthropic.com']
    });

    const updated = store.updateRule({
      ...claudeRule,
      processes: ['Claude', 'claude', '@anthropic-ai/claude-code', 'claude-beta'],
      domains: ['claude.ai', 'api.anthropic.com', 'beta.anthropic.com']
    });

    expect(updated).not.toBeNull();
    expect(updated?.iconDataUrl).toBe(BRAND_ICONS.claude);
    expect(updated?.processes).not.toContain('Claude.exe');
    expect(updated?.processes).toContain('claude-beta');
    expect(updated?.domains).toContain('beta.anthropic.com');

    // Verify persisted state on disk survives reload (R-1)
    const reloaded = new Store(configFile);
    expect(reloaded.getState().rules).toHaveLength(1);
    expect(reloaded.getState().rules[0].iconDataUrl).toBe(BRAND_ICONS.claude);
    expect(reloaded.getState().rules[0].processes).toEqual([
      'Claude',
      'claude',
      '@anthropic-ai/claude-code',
      'claude-beta'
    ]);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('7. S-2 Hosts Injection Attack Prevention in DomainFirewall', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-injection-test-'));
    const mockHosts = path.join(tmpDir, 'hosts');
    fs.writeFileSync(mockHosts, '127.0.0.1 localhost\n', 'utf-8');

    const firewall = new DomainFirewall(mockHosts, true);

    const maliciousRules: ShieldRule[] = [
      {
        id: 'r-malicious',
        name: 'Malicious Rule',
        type: 'domain',
        presetKey: null,
        iconDataUrl: null,
        appPaths: [],
        processes: [],
        domains: [
          'legit.com',
          'x.com\n6.6.6.6 bank.ru',
          'evil.com\r\n1.2.3.4 phish.com',
          'bad domain with spaces.com'
        ]
      }
    ];

    await firewall.syncDomains(maliciousRules, { 'r-malicious': false });
    const hostsContent = fs.readFileSync(mockHosts, 'utf-8');

    expect(hostsContent).toContain('0.0.0.0 legit.com');
    expect(hostsContent).not.toContain('bank.ru');
    expect(hostsContent).not.toContain('6.6.6.6');
    expect(hostsContent).not.toContain('phish.com');
    expect(hostsContent).not.toContain('1.2.3.4');
    expect(hostsContent).not.toContain('bad domain');

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('8. R-1, S-3, B-9 & R-3 Security Validation: Brand SVG Icons, Tracker Fallback, and macOS Full-Path Deny-List', async () => {
    // R-1: All BRAND_ICONS (;utf8, SVG) must be accepted
    for (const [key, dataUrl] of Object.entries(BRAND_ICONS)) {
      expect(isSafeDataUrl(dataUrl), `BRAND_ICONS.${key} should be valid`).toBe(true);
    }
    expect(isSafeDataUrl('data:image/png;base64,iVBORw0KGgo=')).toBe(true);
    expect(isSafeDataUrl('https://evil.tracker.com/pixel.png')).toBe(false);
    expect(isSafeDataUrl('data:image/svg+xml;utf8,<svg onload="alert(1)"></svg>')).toBe(false);
    expect(isSafeDataUrl('javascript:alert(1)')).toBe(false);
    expect(isSafeDataUrl(null)).toBe(true);

    // R-1: Invalid icon replaces iconDataUrl with null instead of rejecting the whole rule
    const ruleWithTrackerIcon = validateAndSanitizeRule({
      name: 'Rule With Bad Icon',
      type: 'app',
      iconDataUrl: 'https://tracker.example.com/leak.png',
      processes: ['claude'],
      domains: ['claude.ai']
    });
    expect(ruleWithTrackerIcon.valid).toBe(true);
    expect(ruleWithTrackerIcon.rule?.iconDataUrl).toBeNull();

    // R-3 & B-9: Deny-listed system processes (including macOS full paths and login shells)
    expect(isDeniedSystemProcess('launchd')).toBe(true);
    expect(isDeniedSystemProcess('/sbin/launchd')).toBe(true);
    expect(
      isDeniedSystemProcess('/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder')
    ).toBe(true);
    expect(isDeniedSystemProcess('/bin/zsh')).toBe(true);
    expect(isDeniedSystemProcess('-zsh')).toBe(true);
    expect(isDeniedSystemProcess('C:\\Windows\\explorer.exe')).toBe(true);
    expect(isDeniedSystemProcess('Terminal')).toBe(true);
    expect(isDeniedSystemProcess('/Applications/Claude.app/Contents/MacOS/Claude')).toBe(false);
    expect(isDeniedSystemProcess('codex')).toBe(false);

    // Verify ProcessGuard never freezes a macOS full-path system process even if a child of a matched process
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-r3-test-'));
    const guard = new ProcessGuard({
      recoveryFilePath: path.join(tmpDir, 'recovery.json'),
      customProcessLister: async () => [
        {
          pid: 99991,
          ppid: 1,
          comm: '/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder',
          args: '/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder'
        },
        {
          pid: 99992,
          ppid: 1,
          comm: '-zsh',
          args: '-zsh'
        }
      ]
    });

    const frozen = await guard.enforce(
      [
        {
          id: 'r-sys',
          name: 'Sys',
          type: 'app',
          presetKey: null,
          iconDataUrl: null,
          appPaths: ['/System/Library/CoreServices/Finder.app'],
          processes: ['Finder', 'zsh'],
          domains: []
        }
      ],
      { 'r-sys': false }
    );
    expect(frozen['r-sys'] || []).toHaveLength(0);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('9. B-1 Concurrency Serialization in ProcessGuard (enforce + unfreezeAll)', async () => {
    const dummyChild = spawn(
      process.execPath,
      ['-e', 'setInterval(() => {}, 500)'],
      { stdio: 'ignore' }
    );
    const pid = dummyChild.pid as number;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-concurrency-test-'));
    const recoveryFile = path.join(tmpDir, 'frozen-recovery.json');

    const guard = new ProcessGuard({
      recoveryFilePath: recoveryFile,
      customProcessLister: async () => [
        {
          pid,
          ppid: process.pid,
          comm: 'dummy-ai',
          args: 'dummy-ai'
        }
      ]
    });

    const rule: ShieldRule = {
      id: 'r-race',
      name: 'Race Test',
      type: 'app',
      presetKey: null,
      iconDataUrl: null,
      appPaths: [],
      processes: ['dummy-ai'],
      domains: []
    };

    try {
      const p1 = guard.enforce([rule], { 'r-race': false });
      const p2 = guard.enforce([rule], { 'r-race': true });
      const p3 = guard.enforce([rule], { 'r-race': false });
      const pUnfreeze = guard.unfreezeAll();

      await Promise.all([p1, p2, p3, pUnfreeze]);

      // After unfreezeAll(), no processes may remain frozen!
      expect(guard.getFrozenSnapshot()['r-race'] || []).toHaveLength(0);
    } finally {
      await guard.unfreezeAll();
      dummyChild.kill('SIGKILL');
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('10. B-3 ProcessGuard Startup Crash Recovery & R-2 IpMonitor Generation Counter', async () => {
    const dummyChild = spawn(
      process.execPath,
      ['-e', 'setInterval(() => {}, 500)'],
      { stdio: 'ignore' }
    );
    const pid = dummyChild.pid as number;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipshield-recovery-test-'));
    const recoveryFile = path.join(tmpDir, 'frozen-recovery.json');

    fs.writeFileSync(
      recoveryFile,
      JSON.stringify([{ pid, comm: 'node', suspendedAt: Date.now() - 5000 }]),
      'utf-8'
    );

    const guard = new ProcessGuard({
      recoveryFilePath: recoveryFile,
      customProcessLister: async () => [
        {
          pid,
          ppid: process.pid,
          comm: process.execPath,
          args: 'node'
        }
      ]
    });

    expect(fs.existsSync(recoveryFile)).toBe(false);

    // R-2: IpMonitor generation increments on interface change and sets fail-closed IP
    const monitor = new IpMonitor();
    const genBefore = monitor.getGeneration();
    monitor.handleInterfaceChange();
    expect(monitor.getGeneration()).toBeGreaterThan(genBefore);
    expect(monitor.getCurrentIp()).toBe('Смена сети...');

    await guard.unfreezeAll();
    dummyChild.kill('SIGKILL');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

