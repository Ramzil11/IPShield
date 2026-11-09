const DEFAULT_DOMAIN_ICON = `data:image/svg+xml;utf8,${encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
    <rect width="64" height="64" rx="16" fill="#0F172A"/>
    <circle cx="32" cy="32" r="17" stroke="#38BDF8" stroke-width="3"/>
    <ellipse cx="32" cy="32" rx="8" ry="17" stroke="#38BDF8" stroke-width="2.5"/>
    <line x1="15" y1="32" x2="49" y2="32" stroke="#38BDF8" stroke-width="2.5"/>
  </svg>`
)}`;

interface UiState {
  tab: 'main' | 'ips';
  editingRuleId: string | null; // null = closed, 'new' = creating, otherwise rule.id
  addMode: 'app' | 'domain';
  editorName: string;
  editorPresetKey: PresetKey;
  editorIconDataUrl: string | null;
  editorProcesses: string[];
  editorDomains: string[];
  appSearchQuery: string;
  quickPickerOpen: boolean;
  quickPickerRuleIds: string[];
  newIpRuleIds: string[];
  newIpRulesInitialized: boolean;
  snapshot: RuntimeSnapshot | null;
  detectedApps: DetectedAppItem[];
}

const ui: UiState = {
  tab: 'main',
  editingRuleId: null,
  addMode: 'app',
  editorName: '',
  editorPresetKey: null,
  editorIconDataUrl: DEFAULT_DOMAIN_ICON,
  editorProcesses: [],
  editorDomains: [],
  appSearchQuery: '',
  quickPickerOpen: false,
  quickPickerRuleIds: [],
  newIpRuleIds: [],
  newIpRulesInitialized: false,
  snapshot: null,
  detectedApps: []
};

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

/**
 * Applies a live IPv4 input mask as the user types:
 * - Strips any non-digit / non-dot characters
 * - Clamps/splits octets > 255 into the next octet
 * - Limits total octets to 4 (XXX.XXX.XXX.XXX)
 */
function applyIpv4Mask(rawInput: string): string {
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

/**
 * Validates strict IPv4 address (e.g. 185.212.44.19).
 */
function isValidIpAddress(raw: string): boolean {
  if (typeof raw !== 'string') return false;
  const s = raw.trim();
  const ipv4Regex = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  return ipv4Regex.test(s);
}

/**
 * Strips protocol/path and validates that the string is a real domain (e.g. claude.ai, api.openai.com).
 * Rejects whitespace and newlines (S-2).
 */
function normalizeAndValidateDomain(raw: string): string | null {
  if (typeof raw !== 'string') return null;
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');

  if (!cleaned) return null;

  if (/[\s\r\n\t]/.test(cleaned)) {
    return null;
  }

  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  if (!domainRegex.test(cleaned)) {
    return null;
  }
  return cleaned;
}

const SYSTEM_PROCESS_DENYLIST_UI = new Set([
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

function isDeniedSystemProcessUi(procName: string): boolean {
  const clean = procName.trim().toLowerCase();
  if (!clean) return true;
  const base = (clean.split(/[/\\]/).pop() || clean)
    .replace(/^-+/, '')
    .replace(/\.exe$/, '');
  return (
    SYSTEM_PROCESS_DENYLIST_UI.has(base) ||
    SYSTEM_PROCESS_DENYLIST_UI.has(`${base}.exe`) ||
    SYSTEM_PROCESS_DENYLIST_UI.has(clean)
  );
}

function getAllowedIpsForRule(ruleId: string): AllowedIpEntry[] {
  if (!ui.snapshot) return [];
  return ui.snapshot.ips.filter(ipEntry => ipEntry.ruleIds.includes(ruleId));
}

function showDomainError(msg: string | null): void {
  const errEl = el<HTMLDivElement>('domain-error-msg');
  const domainBox = el<HTMLDivElement>('domain-tag-box');
  if (msg) {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
    domainBox.classList.add('input-error');
  } else {
    errEl.textContent = '';
    errEl.classList.add('hidden');
    domainBox.classList.remove('input-error');
  }
}

function showRuleEditorError(msg: string | null): void {
  const errEl = el<HTMLDivElement>('rule-editor-error');
  if (msg) {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
  } else {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }
}

function showIpError(msg: string | null): void {
  const errEl = el<HTMLDivElement>('ip-error-msg');
  const ipInput = el<HTMLInputElement>('input-new-ip');
  if (msg) {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
    ipInput.classList.add('input-error');
  } else {
    errEl.textContent = '';
    errEl.classList.add('hidden');
    ipInput.classList.remove('input-error');
  }
}

async function openCreateRuleModal(): Promise<void> {
  if (ui.editingRuleId === 'new') {
    ui.editingRuleId = null;
    renderAll();
    return;
  }

  ui.editingRuleId = 'new';
  ui.addMode = 'app';
  ui.editorName = '';
  ui.editorPresetKey = null;
  ui.editorIconDataUrl = DEFAULT_DOMAIN_ICON;
  ui.editorProcesses = [];
  ui.editorDomains = [];
  ui.appSearchQuery = '';

  el<HTMLInputElement>('editor-rule-name').value = '';
  el<HTMLInputElement>('proc-tag-input').value = '';
  el<HTMLInputElement>('domain-tag-input').value = '';
  el<HTMLInputElement>('app-search-input').value = '';
  showDomainError(null);
  showRuleEditorError(null);

  if (ui.detectedApps.length === 0) {
    ui.detectedApps = await window.ipshield.scanApps();
  }
  renderAll();
}

async function openEditRuleModal(rule: ShieldRule): Promise<void> {
  if (ui.editingRuleId === rule.id) {
    ui.editingRuleId = null;
    renderAll();
    return;
  }

  const combinedProcesses = Array.from(new Set([...rule.appPaths, ...rule.processes]));
  ui.editingRuleId = rule.id;
  ui.addMode = combinedProcesses.length > 0 ? 'app' : 'domain';
  ui.editorName = rule.name;
  ui.editorPresetKey = rule.presetKey;
  ui.editorIconDataUrl = rule.iconDataUrl || DEFAULT_DOMAIN_ICON;
  ui.editorProcesses = combinedProcesses;
  ui.editorDomains = [...rule.domains];
  ui.appSearchQuery = '';

  el<HTMLInputElement>('editor-rule-name').value = rule.name;
  el<HTMLInputElement>('proc-tag-input').value = '';
  el<HTMLInputElement>('domain-tag-input').value = '';
  el<HTMLInputElement>('app-search-input').value = '';
  showDomainError(null);
  showRuleEditorError(null);

  if (ui.detectedApps.length === 0) {
    ui.detectedApps = await window.ipshield.scanApps();
  }
  renderAll();
}

function toggleDetectedAppInEditor(item: DetectedAppItem): void {
  const itemTargets = Array.from(new Set([...item.appPaths, ...item.processes]));
  const isSelected =
    itemTargets.length > 0 && itemTargets.some(target => ui.editorProcesses.includes(target));

  if (isSelected) {
    ui.editorProcesses = ui.editorProcesses.filter(p => !itemTargets.includes(p));
    if (item.isPreset && item.domains.length > 0) {
      ui.editorDomains = ui.editorDomains.filter(d => !item.domains.includes(d));
    }
    if (ui.editorPresetKey === item.presetKey) {
      ui.editorPresetKey = null;
    }
  } else {
    for (const target of itemTargets) {
      if (!ui.editorProcesses.includes(target)) {
        ui.editorProcesses.push(target);
      }
    }
    for (const dom of item.domains) {
      if (!ui.editorDomains.includes(dom)) {
        ui.editorDomains.push(dom);
      }
    }
    ui.editorIconDataUrl = item.iconDataUrl || DEFAULT_DOMAIN_ICON;
    if (item.isPreset) {
      ui.editorPresetKey = item.presetKey;
    }

    const nameInput = el<HTMLInputElement>('editor-rule-name');
    if (!nameInput.value.trim()) {
      const cleanTitle = item.isPreset ? item.name.split(' (')[0] : item.name;
      nameInput.value = cleanTitle;
      ui.editorName = cleanTitle;
    }
  }

  showRuleEditorError(null);
  renderAddModal();
}

function tryAddDomainTokensFromInput(rawText: string): boolean {
  const tokens = rawText
    .split(/[\s,]+/)
    .map(t => t.trim())
    .filter(Boolean);

  if (tokens.length === 0) return true;

  for (const token of tokens) {
    const valid = normalizeAndValidateDomain(token);
    if (!valid) {
      showDomainError(`Некорректный домен «${token}». Пример: claude.ai`);
      return false;
    }
    if (!ui.editorDomains.includes(valid)) {
      ui.editorDomains.push(valid);
    }
  }

  showDomainError(null);
  showRuleEditorError(null);
  return true;
}

function renderTopCard(): void {
  const snap = ui.snapshot;
  if (!snap) return;

  const ipCard = el<HTMLDivElement>('ip-card');
  const statusDot = el<HTMLSpanElement>('status-dot');
  const statusLabel = el<HTMLSpanElement>('status-label');
  const ipLabelTag = el<HTMLSpanElement>('ip-label-tag');
  const currentIpEl = el<HTMLDivElement>('current-ip');
  const btnAllowTop = el<HTMLButtonElement>('btn-allow-top');

  currentIpEl.textContent = snap.currentIp;
  const matchedIpEntry = snap.ips.find(i => i.ip === snap.currentIp);
  ipLabelTag.textContent = matchedIpEntry ? `• ${matchedIpEntry.label}` : '';

  const totalRules = snap.rules.length;
  const openCount = snap.rules.filter(r => snap.ruleStatuses[r.id]?.allowed).length;

  if (totalRules === 0) {
    ipCard.className = 'ip-card state-idle';
    statusDot.className = 'status-dot dot-idle';
    statusLabel.className = 'status-text text-idle';
    statusLabel.textContent = 'Нет правил';
    btnAllowTop.className = 'btn-allow-top';
    btnAllowTop.textContent = '＋ Разрешить IP';
  } else if (openCount === totalRules) {
    ipCard.className = 'ip-card state-open';
    statusDot.className = 'status-dot dot-open';
    statusLabel.className = 'status-text text-open';
    statusLabel.textContent = 'Активен';
    btnAllowTop.className = 'btn-allow-top already-allowed';
    btnAllowTop.textContent = '✓ Разрешён';
  } else if (openCount > 0) {
    ipCard.className = 'ip-card state-partial';
    statusDot.className = 'status-dot dot-partial';
    statusLabel.className = 'status-text text-partial';
    statusLabel.textContent = `Открыто ${openCount} из ${totalRules}`;
    btnAllowTop.className = 'btn-allow-top';
    btnAllowTop.textContent = '＋ Разрешить IP';
  } else {
    ipCard.className = 'ip-card state-blocked';
    statusDot.className = 'status-dot dot-blocked';
    statusLabel.className = 'status-text text-blocked';
    statusLabel.textContent = 'Заблокировано';
    btnAllowTop.className = 'btn-allow-top';
    btnAllowTop.textContent = '＋ Разрешить IP';
  }

  const pickerEl = el<HTMLDivElement>('quick-allow-picker');
  pickerEl.classList.toggle('hidden', !ui.quickPickerOpen);

  if (ui.quickPickerOpen) {
    const chipsContainer = el<HTMLDivElement>('picker-chips');
    chipsContainer.innerHTML = '';

    if (snap.rules.length === 0) {
      const span = document.createElement('span');
      span.style.fontSize = '12px';
      span.style.color = 'rgba(255,255,255,0.45)';
      span.textContent = 'Сначала добавьте хотя бы одно правило ниже';
      chipsContainer.appendChild(span);
    } else {
      for (const rule of snap.rules) {
        const selected = ui.quickPickerRuleIds.includes(rule.id);
        const btn = document.createElement('button');
        btn.className = `chip-btn ${selected ? 'selected' : ''}`;
        btn.textContent = rule.name;
        btn.onclick = () => {
          if (ui.quickPickerRuleIds.includes(rule.id)) {
            ui.quickPickerRuleIds = ui.quickPickerRuleIds.filter(id => id !== rule.id);
          } else {
            ui.quickPickerRuleIds.push(rule.id);
          }
          renderTopCard();
        };
        chipsContainer.appendChild(btn);
      }
    }
  }

  const hasDomainRules = snap.rules.some(r => r.domains.length > 0);
  const banner = el<HTMLDivElement>('elevation-banner');
  banner.classList.toggle('hidden', !(hasDomainRules && !snap.firewallElevated));

  const procGuardBanner = el<HTMLDivElement>('process-guard-banner');
  const guardError =
    snap.processGuardError || (snap.firewallElevated ? snap.firewallError : null);
  if (guardError) {
    procGuardBanner.textContent = guardError;
    procGuardBanner.classList.remove('hidden');
  } else {
    procGuardBanner.textContent = '';
    procGuardBanner.classList.add('hidden');
  }

  renderUpdateBanner();
}

function renderUpdateBanner(): void {
  const banner = el<HTMLDivElement>('update-banner');
  if (!banner) return;

  const upd = ui.snapshot?.update;
  if (
    !upd ||
    upd.dismissed ||
    !upd.latestVersion ||
    upd.phase === 'idle' ||
    upd.phase === 'checking'
  ) {
    banner.classList.add('hidden');
    return;
  }

  banner.classList.remove('hidden');

  const iconEl = el<HTMLSpanElement>('update-icon');
  const labelEl = el<HTMLSpanElement>('update-label');
  const verTextEl = el<HTMLSpanElement>('update-version-text');
  const verLinkBtn = el<HTMLButtonElement>('version-link');
  const pctEl = el<HTMLSpanElement>('update-progress-pct');
  const actionBtn = el<HTMLButtonElement>('btn-update-action');
  const dismissBtn = el<HTMLButtonElement>('btn-update-dismiss');
  const progressWrap = el<HTMLDivElement>('update-progress-wrap');
  const progressFill = el<HTMLDivElement>('update-progress-fill');

  const verTag = upd.latestVersion.startsWith('v') ? upd.latestVersion : `v${upd.latestVersion}`;
  verTextEl.textContent = verTag;
  verLinkBtn.title = `Открыть релиз ${verTag} на GitHub`;

  if (upd.phase === 'available') {
    banner.className = 'update-banner state-available';
    iconEl.innerHTML = '⬇';
    labelEl.textContent = 'Доступно обновление';
    pctEl.classList.add('hidden');
    progressWrap.classList.add('hidden');
    actionBtn.classList.remove('hidden');
    actionBtn.textContent = 'Обновить';
    dismissBtn.classList.remove('hidden');
  } else if (upd.phase === 'downloading') {
    banner.className = 'update-banner state-downloading';
    iconEl.innerHTML = '<span class="spin">↻</span>';
    labelEl.textContent = 'Скачивание';
    const pct = Math.max(0, Math.min(100, Math.round(upd.downloadProgress || 0)));
    pctEl.textContent = `${pct}%`;
    pctEl.classList.remove('hidden');
    progressWrap.classList.remove('hidden');
    progressFill.style.width = `${pct}%`;
    actionBtn.classList.add('hidden');
    dismissBtn.classList.add('hidden');
  } else if (upd.phase === 'ready') {
    banner.className = 'update-banner state-ready';
    iconEl.innerHTML = '✓';
    labelEl.textContent = 'Готово к установке';
    pctEl.classList.add('hidden');
    progressWrap.classList.add('hidden');
    actionBtn.classList.remove('hidden');
    actionBtn.textContent = 'Перезапустить';
    dismissBtn.classList.remove('hidden');
  } else if (upd.phase === 'error') {
    banner.className = 'update-banner state-error';
    iconEl.innerHTML = '!';
    labelEl.textContent = 'Ошибка обновления';
    pctEl.classList.add('hidden');
    progressWrap.classList.add('hidden');
    actionBtn.classList.remove('hidden');
    actionBtn.textContent = 'Повторить';
    dismissBtn.classList.remove('hidden');
  }
}

function renderAddModal(): void {
  const modal = el<HTMLDivElement>('add-modal');
  const isOpen = ui.editingRuleId !== null;
  modal.classList.toggle('hidden', !isOpen);
  if (!isOpen) return;

  const isAppMode = ui.addMode === 'app';
  el<HTMLButtonElement>('mode-btn-app').classList.toggle('active', isAppMode);
  el<HTMLButtonElement>('mode-btn-domain').classList.toggle('active', !isAppMode);
  el<HTMLDivElement>('add-mode-app').classList.toggle('hidden', !isAppMode);
  el<HTMLDivElement>('add-mode-domain').classList.toggle('hidden', isAppMode);

  // Update count badges on the segmented switch
  const appBadge = el<HTMLSpanElement>('badge-app-count');
  appBadge.textContent = String(ui.editorProcesses.length);
  appBadge.classList.toggle('hidden', ui.editorProcesses.length === 0);

  const domBadge = el<HTMLSpanElement>('badge-domain-count');
  domBadge.textContent = String(ui.editorDomains.length);
  domBadge.classList.toggle('hidden', ui.editorDomains.length === 0);

  // Render Process Chips inside #editor-proc-chips
  const procChipsEl = el<HTMLDivElement>('editor-proc-chips');
  procChipsEl.innerHTML = '';
  for (const proc of ui.editorProcesses) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip';

    const txt = document.createElement('span');
    txt.className = 'tag-chip-text';
    txt.textContent = proc;

    const rmBtn = document.createElement('button');
    rmBtn.type = 'button';
    rmBtn.className = 'tag-chip-remove';
    rmBtn.textContent = '✕';
    rmBtn.onclick = ev => {
      ev.stopPropagation();
      ui.editorProcesses = ui.editorProcesses.filter(p => p !== proc);
      renderAddModal();
    };

    chip.appendChild(txt);
    chip.appendChild(rmBtn);
    procChipsEl.appendChild(chip);
  }

  // Render Domain Chips inside #editor-domain-chips
  const domChipsEl = el<HTMLDivElement>('editor-domain-chips');
  domChipsEl.innerHTML = '';
  for (const dom of ui.editorDomains) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip mono';

    const txt = document.createElement('span');
    txt.className = 'tag-chip-text';
    txt.textContent = dom;

    const rmBtn = document.createElement('button');
    rmBtn.type = 'button';
    rmBtn.className = 'tag-chip-remove';
    rmBtn.textContent = '✕';
    rmBtn.onclick = ev => {
      ev.stopPropagation();
      ui.editorDomains = ui.editorDomains.filter(d => d !== dom);
      renderAddModal();
    };

    chip.appendChild(txt);
    chip.appendChild(rmBtn);
    domChipsEl.appendChild(chip);
  }

  // Render searchable catalog of presets & installed PC apps
  if (isAppMode) {
    const listEl = el<HTMLDivElement>('detected-apps-list');
    listEl.innerHTML = '';

    const q = ui.appSearchQuery.trim().toLowerCase();
    const filtered = ui.detectedApps.filter(
      item =>
        !q ||
        item.name.toLowerCase().includes(q) ||
        item.subtitle.toLowerCase().includes(q)
    );

    if (filtered.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-box';
      empty.style.padding = '14px';
      empty.textContent = 'Ничего не найдено';
      listEl.appendChild(empty);
      return;
    }

    for (const item of filtered) {
      const itemTargets = Array.from(new Set([...item.appPaths, ...item.processes]));
      const selected =
        itemTargets.length > 0 && itemTargets.some(t => ui.editorProcesses.includes(t));

      const row = document.createElement('div');
      row.className = `picker-item ${selected ? 'selected' : ''}`;

      const left = document.createElement('div');
      left.className = 'item-left';

      const img = document.createElement('img');
      img.className = 'app-icon';
      img.src = item.iconDataUrl || DEFAULT_DOMAIN_ICON;
      img.alt = item.name;

      const titles = document.createElement('div');
      titles.className = 'item-titles';

      const nameDiv = document.createElement('div');
      nameDiv.className = 'item-name';
      nameDiv.textContent = item.name;

      const subDiv = document.createElement('div');
      subDiv.className = 'item-sub';
      subDiv.textContent = item.subtitle;

      titles.appendChild(nameDiv);
      titles.appendChild(subDiv);
      left.appendChild(img);
      left.appendChild(titles);

      const badge = document.createElement('span');
      badge.className = `picker-badge ${selected ? 'selected' : ''}`;
      badge.textContent = selected ? '✓ Выбрано' : '＋ Выбрать';

      row.appendChild(left);
      row.appendChild(badge);

      row.onclick = () => {
        toggleDetectedAppInEditor(item);
      };

      listEl.appendChild(row);
    }
  }
}

function renderRulesList(): void {
  const snap = ui.snapshot;
  const container = el<HTMLDivElement>('rules-list');
  container.innerHTML = '';
  if (!snap) return;

  if (snap.rules.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-box';
    empty.textContent = 'Нажмите «＋ Добавить», чтобы выбрать Claude, Codex, приложения или домены';
    container.appendChild(empty);
    return;
  }

  for (const rule of snap.rules) {
    const status = snap.ruleStatuses[rule.id];
    const allowed = Boolean(status?.allowed);
    const allowedIps = getAllowedIpsForRule(rule.id);
    const ipSummary =
      allowedIps.length === 0
        ? 'Нет разрешённых IP'
        : allowedIps.map(x => x.ip).join(', ');
    const isEditing = ui.editingRuleId === rule.id;

    const card = document.createElement('div');
    card.className = `rule-card ${allowed ? 'open' : 'blocked'} ${isEditing ? 'editing' : ''}`;
    card.title = 'Нажмите, чтобы редактировать процессы и домены правила';
    card.onclick = () => {
      void openEditRuleModal(rule);
    };

    const row = document.createElement('div');
    row.className = 'rule-row';

    const left = document.createElement('div');
    left.className = 'item-left';

    const icon = document.createElement('img');
    icon.className = 'app-icon';
    icon.src = rule.iconDataUrl || DEFAULT_DOMAIN_ICON;
    icon.alt = rule.name;

    const titles = document.createElement('div');
    titles.className = 'item-titles';

    const nameEl = document.createElement('div');
    nameEl.className = 'item-name';
    nameEl.textContent = rule.name;

    const subEl = document.createElement('div');
    subEl.className = 'item-sub';
    subEl.textContent = ipSummary;

    titles.appendChild(nameEl);
    titles.appendChild(subEl);
    left.appendChild(icon);
    left.appendChild(titles);

    const right = document.createElement('div');
    right.className = 'rule-right';

    const stateEl = document.createElement('span');
    stateEl.className = `rule-state ${allowed ? 'open' : 'blocked'}`;
    const dot = document.createElement('span');
    dot.className = `status-dot ${allowed ? 'dot-open' : 'dot-blocked'}`;
    dot.style.width = '6px';
    dot.style.height = '6px';
    stateEl.appendChild(dot);
    stateEl.appendChild(document.createTextNode(allowed ? 'Открыт' : 'Блок'));

    const delBtn = document.createElement('button');
    delBtn.className = 'delete-btn';
    delBtn.textContent = '✕';
    delBtn.title = 'Удалить правило';
    delBtn.onclick = async ev => {
      ev.stopPropagation();
      if (ui.editingRuleId === rule.id) {
        ui.editingRuleId = null;
      }
      const next = await window.ipshield.removeRule(rule.id);
      ui.snapshot = next;
      ui.newIpRuleIds = ui.newIpRuleIds.filter(id => id !== rule.id);
      renderAll();
    };

    right.appendChild(stateEl);
    right.appendChild(delBtn);

    row.appendChild(left);
    row.appendChild(right);
    card.appendChild(row);

    container.appendChild(card);
  }
}

function renderIpsTab(): void {
  const snap = ui.snapshot;
  const container = el<HTMLDivElement>('ips-list');
  const rulesSection = el<HTMLDivElement>('new-ip-rules-section');
  const newIpChips = el<HTMLDivElement>('new-ip-chips');

  container.innerHTML = '';
  newIpChips.innerHTML = '';
  if (!snap) return;

  if (snap.rules.length === 0) {
    rulesSection.classList.add('hidden');
  } else {
    rulesSection.classList.remove('hidden');
    for (const rule of snap.rules) {
      const selected = ui.newIpRuleIds.includes(rule.id);
      const chip = document.createElement('button');
      chip.className = `chip-btn ${selected ? 'selected' : ''}`;
      chip.textContent = rule.name;
      chip.onclick = () => {
        if (ui.newIpRuleIds.includes(rule.id)) {
          ui.newIpRuleIds = ui.newIpRuleIds.filter(id => id !== rule.id);
        } else {
          ui.newIpRuleIds.push(rule.id);
        }
        renderIpsTab();
      };
      newIpChips.appendChild(chip);
    }
  }

  if (snap.ips.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-box';
    empty.textContent = 'Список разрешённых IP пуст';
    container.appendChild(empty);
    return;
  }

  for (const entry of snap.ips) {
    const isCurrent = entry.ip === snap.currentIp;
    const card = document.createElement('div');
    card.className = `ip-card-item ${isCurrent ? 'active-ip' : ''}`;

    const topRow = document.createElement('div');
    topRow.className = 'rule-row';

    const left = document.createElement('div');
    left.style.display = 'flex';
    left.style.alignItems = 'center';
    left.style.gap = '8px';

    const ipText = document.createElement('span');
    ipText.style.fontFamily = "'SF Mono', monospace";
    ipText.style.fontWeight = '700';
    ipText.style.fontSize = '13px';
    ipText.textContent = entry.ip;

    const labelText = document.createElement('span');
    labelText.style.fontSize = '12px';
    labelText.style.color = 'rgba(255,255,255,0.42)';
    labelText.textContent = entry.label;

    left.appendChild(ipText);
    left.appendChild(labelText);

    const delBtn = document.createElement('button');
    delBtn.className = 'delete-btn';
    delBtn.textContent = '✕';
    delBtn.onclick = async () => {
      ui.snapshot = await window.ipshield.removeIp(entry.ip);
      renderAll();
    };

    topRow.appendChild(left);
    topRow.appendChild(delBtn);
    card.appendChild(topRow);

    if (snap.rules.length > 0) {
      const chipsWrap = document.createElement('div');
      chipsWrap.className = 'chips-wrap';

      for (const rule of snap.rules) {
        const active = entry.ruleIds.includes(rule.id);
        const chip = document.createElement('button');
        chip.className = `chip-btn ${active ? 'selected-green' : ''}`;
        chip.textContent = rule.name;
        chip.onclick = async () => {
          ui.snapshot = await window.ipshield.toggleRuleOnIp(entry.ip, rule.id);
          renderAll();
        };
        chipsWrap.appendChild(chip);
      }

      card.appendChild(chipsWrap);
    }

    container.appendChild(card);
  }
}

function renderAll(): void {
  const isMain = ui.tab === 'main';
  el<HTMLElement>('view-main').classList.toggle('hidden', !isMain);
  el<HTMLElement>('view-ips').classList.toggle('hidden', isMain);
  el<HTMLButtonElement>('tab-main').classList.toggle('active', isMain);
  el<HTMLButtonElement>('tab-ips').classList.toggle('active', !isMain);

  renderTopCard();
  renderAddModal();
  renderRulesList();
  renderIpsTab();
}

async function saveRuleFromEditor(): Promise<void> {
  const procInput = el<HTMLInputElement>('proc-tag-input');
  if (procInput.value.trim()) {
    const rawProcs = procInput.value
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    for (const p of rawProcs) {
      if (!ui.editorProcesses.includes(p)) {
        ui.editorProcesses.push(p);
      }
    }
    procInput.value = '';
  }

  const domInput = el<HTMLInputElement>('domain-tag-input');
  if (domInput.value.trim()) {
    const ok = tryAddDomainTokensFromInput(domInput.value);
    if (!ok) {
      ui.addMode = 'domain';
      renderAddModal();
      return;
    }
    domInput.value = '';
  }

  if (ui.editorProcesses.length === 0 && ui.editorDomains.length === 0) {
    showRuleEditorError('Выберите приложение или добавьте хотя бы один домен');
    return;
  }

  showRuleEditorError(null);
  showDomainError(null);

  const nameInput = el<HTMLInputElement>('editor-rule-name');
  const fallbackName =
    ui.editorProcesses.length > 0
      ? ui.editorProcesses[0].replace(/^.*[\\/]/, '').replace(/\.(app|exe)$/i, '')
      : ui.editorDomains[0];
  const finalName = nameInput.value.trim() || fallbackName || 'Правило';

  // Separate bundle/full paths from process/CLI names
  const appPaths: string[] = [];
  const processes: string[] = [];
  for (const item of ui.editorProcesses) {
    if (item.startsWith('/') || item.includes(':\\') || item.toLowerCase().endsWith('.app')) {
      appPaths.push(item);
    } else {
      processes.push(item);
    }
  }

  const ruleType: RuleType = ui.editorPresetKey
    ? 'preset'
    : ui.editorProcesses.length > 0
    ? 'app'
    : 'domain';

  if (ui.editingRuleId === 'new') {
    const prevIds = ui.snapshot ? ui.snapshot.rules.map(r => r.id) : [];
    const next = await window.ipshield.addRule({
      name: finalName,
      type: ruleType,
      presetKey: ui.editorPresetKey,
      iconDataUrl: ui.editorIconDataUrl || DEFAULT_DOMAIN_ICON,
      appPaths,
      processes,
      domains: [...ui.editorDomains]
    });
    ui.snapshot = next;
    for (const r of next.rules) {
      if (!prevIds.includes(r.id) && !ui.newIpRuleIds.includes(r.id)) {
        ui.newIpRuleIds.push(r.id);
      }
    }
  } else if (ui.editingRuleId) {
    ui.snapshot = await window.ipshield.updateRule({
      id: ui.editingRuleId,
      name: finalName,
      type: ruleType,
      presetKey: ui.editorPresetKey,
      iconDataUrl: ui.editorIconDataUrl || DEFAULT_DOMAIN_ICON,
      appPaths,
      processes,
      domains: [...ui.editorDomains]
    });
  }

  ui.editingRuleId = null;
  renderAll();
}

async function init(): Promise<void> {
  el<HTMLButtonElement>('tab-main').onclick = () => {
    ui.tab = 'main';
    renderAll();
  };
  el<HTMLButtonElement>('tab-ips').onclick = () => {
    ui.tab = 'ips';
    if (!ui.newIpRulesInitialized && ui.snapshot) {
      ui.newIpRuleIds = ui.snapshot.rules.map(r => r.id);
      ui.newIpRulesInitialized = true;
    }
    renderAll();
  };

  el<HTMLButtonElement>('btn-allow-top').onclick = () => {
    ui.quickPickerOpen = !ui.quickPickerOpen;
    if (ui.quickPickerOpen && ui.snapshot) {
      ui.quickPickerRuleIds = ui.snapshot.rules.map(r => r.id);
    }
    renderTopCard();
  };

  el<HTMLButtonElement>('btn-select-all-picker').onclick = () => {
    if (ui.snapshot) {
      ui.quickPickerRuleIds = ui.snapshot.rules.map(r => r.id);
      renderTopCard();
    }
  };

  el<HTMLButtonElement>('btn-confirm-allow').onclick = async () => {
    if (!ui.snapshot) return;
    const ip = ui.snapshot.currentIp;
    if (!isValidIpAddress(ip)) return;
    ui.snapshot = await window.ipshield.addOrUpdateIp({
      ip,
      label: 'Мой IP',
      ruleIds: ui.quickPickerRuleIds
    });
    ui.quickPickerOpen = false;
    renderAll();
  };

  el<HTMLButtonElement>('btn-elevate').onclick = async () => {
    ui.snapshot = await window.ipshield.enableFirewallAccess();
    renderAll();
  };

  el<HTMLButtonElement>('btn-open-add').onclick = () => {
    void openCreateRuleModal();
  };

  el<HTMLButtonElement>('btn-close-add').onclick = () => {
    ui.editingRuleId = null;
    showDomainError(null);
    showRuleEditorError(null);
    renderAll();
  };

  el<HTMLButtonElement>('mode-btn-app').onclick = () => {
    ui.addMode = 'app';
    showDomainError(null);
    renderAddModal();
  };

  el<HTMLButtonElement>('mode-btn-domain').onclick = () => {
    ui.addMode = 'domain';
    showDomainError(null);
    renderAddModal();
  };

  el<HTMLInputElement>('editor-rule-name').oninput = ev => {
    ui.editorName = (ev.target as HTMLInputElement).value;
  };

  // Focus inner input when clicking anywhere inside the Tag-Input boxes
  el<HTMLDivElement>('proc-tag-box').onclick = () => {
    el<HTMLInputElement>('proc-tag-input').focus();
  };
  el<HTMLDivElement>('domain-tag-box').onclick = () => {
    el<HTMLInputElement>('domain-tag-input').focus();
  };

  // Process Tag-Input keyboard handler
  el<HTMLInputElement>('proc-tag-input').onkeydown = ev => {
    const input = ev.target as HTMLInputElement;
    if (ev.key === 'Enter' || ev.key === ',') {
      ev.preventDefault();
      const val = input.value.replace(/,/g, '').trim();
      if (val) {
        if (isDeniedSystemProcessUi(val)) {
          showRuleEditorError(`Системный процесс «${val}» защищён от заморозки`);
          return;
        }
        if (!ui.editorProcesses.includes(val)) {
          ui.editorProcesses.push(val);
          showRuleEditorError(null);
        }
      }
      input.value = '';
      renderAddModal();
    } else if (ev.key === 'Backspace' && input.value === '' && ui.editorProcesses.length > 0) {
      ui.editorProcesses.pop();
      renderAddModal();
    }
  };

  // Domain Tag-Input keyboard & paste handler
  el<HTMLInputElement>('domain-tag-input').onkeydown = ev => {
    const input = ev.target as HTMLInputElement;
    if (ev.key === 'Enter' || ev.key === ',' || ev.key === ' ') {
      ev.preventDefault();
      const raw = input.value.replace(/[, ]/g, '').trim();
      if (!raw) return;
      if (tryAddDomainTokensFromInput(raw)) {
        input.value = '';
        renderAddModal();
      }
    } else if (ev.key === 'Backspace' && input.value === '' && ui.editorDomains.length > 0) {
      ui.editorDomains.pop();
      renderAddModal();
    }
  };

  el<HTMLInputElement>('domain-tag-input').oninput = ev => {
    const target = ev.target as HTMLInputElement;
    const filtered = target.value.replace(/[^a-zA-Z0-9.\-:/,\s]/g, '');
    if (filtered !== target.value) {
      target.value = filtered;
    }
    // If user pasted comma/space-separated domains, convert complete tokens immediately
    if (/[, \n]/.test(target.value)) {
      const parts = target.value.split(/[, \n]+/);
      const completeTokens = parts.slice(0, -1).filter(Boolean);
      const remainder = parts[parts.length - 1] || '';
      if (completeTokens.length > 0 && tryAddDomainTokensFromInput(completeTokens.join(' '))) {
        target.value = remainder;
        renderAddModal();
        return;
      }
    }
    showDomainError(null);
  };

  el<HTMLInputElement>('app-search-input').oninput = ev => {
    ui.appSearchQuery = (ev.target as HTMLInputElement).value;
    renderAddModal();
  };

  el<HTMLButtonElement>('btn-save-rule').onclick = () => {
    void saveRuleFromEditor();
  };

  el<HTMLInputElement>('input-new-ip').oninput = ev => {
    const target = ev.target as HTMLInputElement;
    const masked = applyIpv4Mask(target.value);
    if (masked !== target.value) {
      target.value = masked;
    }
    showIpError(null);
  };

  el<HTMLButtonElement>('btn-new-ip-select-all').onclick = () => {
    if (ui.snapshot) {
      ui.newIpRuleIds = ui.snapshot.rules.map(r => r.id);
      renderIpsTab();
    }
  };

  el<HTMLButtonElement>('btn-add-ip').onclick = async () => {
    const ipInput = el<HTMLInputElement>('input-new-ip');
    const labelInput = el<HTMLInputElement>('input-new-label');
    const ip = ipInput.value.trim();

    if (!ip) {
      showIpError('Введите IP-адрес');
      return;
    }

    if (!isValidIpAddress(ip)) {
      showIpError('Некорректный IP-адрес. Пример: 185.212.44.19');
      return;
    }

    showIpError(null);

    ui.snapshot = await window.ipshield.addOrUpdateIp({
      ip,
      label: labelInput.value.trim() || 'VPN',
      ruleIds: [...ui.newIpRuleIds]
    });
    ipInput.value = '';
    labelInput.value = '';
    renderAll();
  };

  el<HTMLDivElement>('current-ip').onclick = async () => {
    ui.snapshot = await window.ipshield.refreshIp();
    renderAll();
  };

  const versionLinkBtn = el<HTMLButtonElement>('version-link');
  if (versionLinkBtn) {
    versionLinkBtn.onclick = () => {
      void window.ipshield.openReleaseUrl();
    };
  }

  const updateActionBtn = el<HTMLButtonElement>('btn-update-action');
  if (updateActionBtn) {
    updateActionBtn.onclick = async () => {
      const phase = ui.snapshot?.update?.phase;
      if (phase === 'ready') {
        updateActionBtn.textContent = 'Перезапуск...';
        await window.ipshield.applyUpdate();
      } else {
        ui.snapshot = await window.ipshield.startUpdate();
        renderAll();
      }
    };
  }

  const updateDismissBtn = el<HTMLButtonElement>('btn-update-dismiss');
  if (updateDismissBtn) {
    updateDismissBtn.onclick = async () => {
      ui.snapshot = await window.ipshield.dismissUpdate();
      renderAll();
    };
  }

  window.ipshield.onSnapshotUpdate(snap => {
    const prevSig = ui.snapshot
      ? JSON.stringify({
          ip: ui.snapshot.currentIp,
          r: ui.snapshot.rules,
          i: ui.snapshot.ips,
          s: ui.snapshot.ruleStatuses,
          e: ui.snapshot.firewallElevated,
          fe: ui.snapshot.firewallError,
          pe: ui.snapshot.processGuardError,
          u: ui.snapshot.update
        })
      : '';
    const nextSig = JSON.stringify({
      ip: snap.currentIp,
      r: snap.rules,
      i: snap.ips,
      s: snap.ruleStatuses,
      e: snap.firewallElevated,
      fe: snap.firewallError,
      pe: snap.processGuardError,
      u: snap.update
    });

    ui.snapshot = snap;
    if (!ui.newIpRulesInitialized) {
      ui.newIpRuleIds = snap.rules.map(r => r.id);
      ui.newIpRulesInitialized = true;
    }
    if (prevSig !== nextSig) {
      renderAll();
    }
  });

  ui.snapshot = await window.ipshield.getSnapshot();
  ui.newIpRuleIds = ui.snapshot.rules.map(r => r.id);
  ui.newIpRulesInitialized = true;
  renderAll();
}

void init();
