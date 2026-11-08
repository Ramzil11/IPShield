import fs from 'fs';
import os from 'os';
import path from 'path';
import { app } from 'electron';
import { DetectedAppItem, PresetKey } from '../shared/types';
import { BRAND_ICONS } from '../shared/brandIcons';

interface PresetDefinition {
  id: string;
  name: string;
  subtitle: string;
  presetKey: PresetKey;
  defaultIcon: string;
  macAppNames: string[];
  winExeNames: string[];
  processes: string[];
  domains: string[];
}

const PRESETS: PresetDefinition[] = [
  {
    id: 'preset-claude',
    name: 'Claude (Desktop + Claude Code)',
    subtitle: 'Claude App, claude CLI + домены Anthropic',
    presetKey: 'claude',
    defaultIcon: BRAND_ICONS.claude,
    macAppNames: ['Claude.app'],
    winExeNames: ['Claude.exe'],
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
    id: 'preset-codex',
    name: 'Codex & ChatGPT',
    subtitle: 'Codex CLI, ChatGPT App + домены OpenAI',
    presetKey: 'codex',
    defaultIcon: BRAND_ICONS.codex,
    macAppNames: ['ChatGPT.app', 'Codex.app'],
    winExeNames: ['ChatGPT.exe', 'codex.exe'],
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
  },
  {
    id: 'preset-cursor',
    name: 'Cursor',
    subtitle: 'Cursor IDE + домены cursor.com / cursor.sh',
    presetKey: 'cursor',
    defaultIcon: BRAND_ICONS.cursor,
    macAppNames: ['Cursor.app'],
    winExeNames: ['Cursor.exe'],
    processes: ['Cursor', 'Cursor.exe'],
    domains: ['cursor.com', 'www.cursor.com', 'api2.cursor.sh', 'cursor.sh']
  },
  {
    id: 'preset-perplexity',
    name: 'Perplexity',
    subtitle: 'Perplexity App + домены perplexity.ai',
    presetKey: 'perplexity',
    defaultIcon: BRAND_ICONS.perplexity,
    macAppNames: ['Perplexity.app'],
    winExeNames: ['Perplexity.exe'],
    processes: ['Perplexity', 'Perplexity.exe'],
    domains: ['perplexity.ai', 'www.perplexity.ai', 'api.perplexity.ai']
  },
  {
    id: 'preset-gemini',
    name: 'Gemini',
    subtitle: 'Gemini CLI & Web + домены Google AI',
    presetKey: 'gemini',
    defaultIcon: BRAND_ICONS.gemini,
    macAppNames: ['Gemini.app'],
    winExeNames: ['Gemini.exe'],
    processes: ['gemini', '@google/gemini-cli'],
    domains: [
      'gemini.google.com',
      'aistudio.google.com',
      'generativelanguage.googleapis.com'
    ]
  }
];

async function getNativeIconDataUrl(targetPath: string): Promise<string | null> {
  try {
    if (!app || !fs.existsSync(targetPath)) return null;
    const icon = await app.getFileIcon(targetPath, { size: 'normal' });
    if (icon && !icon.isEmpty()) {
      return icon.toDataURL();
    }
  } catch {
    // Fallback to brand/default icon
  }
  return null;
}

export async function scanAvailableApps(): Promise<DetectedAppItem[]> {
  const results: DetectedAppItem[] = [];
  const platform = process.platform;
  const seenAppPaths = new Set<string>();

  // 1. Build rich presets (Claude, Codex, Cursor, etc.) with authentic icons
  for (const preset of PRESETS) {
    const foundPaths: string[] = [];
    let resolvedIcon: string = preset.defaultIcon;

    if (platform === 'darwin') {
      const searchDirs = ['/Applications', path.join(os.homedir(), 'Applications')];
      for (const dir of searchDirs) {
        for (const appName of preset.macAppNames) {
          const full = path.join(dir, appName);
          if (fs.existsSync(full)) {
            foundPaths.push(full);
            seenAppPaths.add(full);
            // Preset icons are retained for Claude and Codex; native app icons are used for other apps
            if (preset.presetKey !== 'claude' && preset.presetKey !== 'codex') {
              const nativeIcon = await getNativeIconDataUrl(full);
              if (nativeIcon) resolvedIcon = nativeIcon;
            }
          }
        }
      }
    }

    results.push({
      id: preset.id,
      name: preset.name,
      subtitle: preset.subtitle,
      isPreset: true,
      presetKey: preset.presetKey,
      iconDataUrl: resolvedIcon,
      appPaths: foundPaths,
      processes: preset.processes,
      domains: preset.domains
    });
  }

  // 2. Scan installed native applications on the user's computer
  if (platform === 'darwin') {
    const appDirs = ['/Applications', path.join(os.homedir(), 'Applications')];
    for (const dir of appDirs) {
      if (!fs.existsSync(dir)) continue;
      let entries: string[] = [];
      try {
        entries = fs.readdirSync(dir);
      } catch {
        continue;
      }

      for (const entry of entries) {
        if (!entry.endsWith('.app')) continue;
        const fullPath = path.join(dir, entry);
        if (seenAppPaths.has(fullPath)) continue;
        seenAppPaths.add(fullPath);

        const cleanName = entry.replace(/\.app$/i, '');
        const nativeIcon = await getNativeIconDataUrl(fullPath);

        results.push({
          id: `app-${cleanName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
          name: cleanName,
          subtitle: fullPath,
          isPreset: false,
          presetKey: null,
          iconDataUrl: nativeIcon || BRAND_ICONS.domain,
          appPaths: [fullPath],
          processes: [cleanName],
          domains: []
        });
      }
    }
  } else if (platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    const progFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const searchRoots = [path.join(localAppData, 'Programs'), progFiles];

    for (const root of searchRoots) {
      if (!fs.existsSync(root)) continue;
      let subdirs: string[] = [];
      try {
        subdirs = fs.readdirSync(root).slice(0, 40);
      } catch {
        continue;
      }
      for (const sub of subdirs) {
        const subPath = path.join(root, sub);
        try {
          if (!fs.statSync(subPath).isDirectory()) continue;
          const files = fs.readdirSync(subPath);
          const exe = files.find(f => f.toLowerCase().endsWith('.exe') && !f.toLowerCase().includes('uninstall'));
          if (exe) {
            const fullExe = path.join(subPath, exe);
            if (seenAppPaths.has(fullExe)) continue;
            seenAppPaths.add(fullExe);
            const cleanName = exe.replace(/\.exe$/i, '');
            const nativeIcon = await getNativeIconDataUrl(fullExe);
            results.push({
              id: `win-${cleanName.toLowerCase()}`,
              name: cleanName,
              subtitle: fullExe,
              isPreset: false,
              presetKey: null,
              iconDataUrl: nativeIcon || BRAND_ICONS.domain,
              appPaths: [fullExe],
              processes: [cleanName, exe],
              domains: []
            });
          }
        } catch {
          // ignore permission errors
        }
      }
    }
  }

  return results;
}

