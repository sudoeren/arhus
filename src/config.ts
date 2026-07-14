import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import type { ArhusConfig } from './types';
import { Severity } from './types';

const defaults: ArhusConfig = {
  include: ['**/*.{ts,tsx,js,jsx}'],
  exclude: ['node_modules/**', 'dist/**', '.git/**', 'coverage/**', '**/*.test.*', '**/test/**', 'tests/**'],
  rules: {},
};

const VALID_TOP_LEVEL_KEYS = new Set(['include', 'exclude', 'rules']);

function findConfigUp(from: string): string | null {
  let dir = resolve(from);
  const root = dirname(dir);

  while (true) {
    const p = resolve(dir, '.arhusrc');
    if (existsSync(p)) return p;
    if (dir === root) break;
    dir = dirname(dir);
  }

  const rootConfig = resolve(root, '.arhusrc');
  if (existsSync(rootConfig)) return rootConfig;

  return null;
}

export function validateConfig(raw: string, configPath: string): string[] {
  const warnings: string[] = [];
  let parsed: Record<string, unknown>;

  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch (err) {
    warnings.push(`${configPath}: Invalid JSON — ${(err as Error).message}`);
    return warnings;
  }

  for (const key of Object.keys(parsed)) {
    if (!VALID_TOP_LEVEL_KEYS.has(key)) {
      warnings.push(`${configPath}: Unknown config key "${key}"`);
    }
  }

  if (parsed['include'] !== undefined && !Array.isArray(parsed['include'])) {
    warnings.push(`${configPath}: "include" must be an array of glob patterns`);
  }

  if (parsed['exclude'] !== undefined && !Array.isArray(parsed['exclude'])) {
    warnings.push(`${configPath}: "exclude" must be an array of glob patterns`);
  }

  if (parsed['rules'] !== undefined && typeof parsed['rules'] === 'object' && !Array.isArray(parsed['rules'])) {
    const rulesConfig = parsed['rules'] as Record<string, unknown>;
    for (const [ruleId, setting] of Object.entries(rulesConfig)) {
      if (setting === false || setting === true) continue;
      if (typeof setting === 'string') {
        if (!Object.values(Severity).includes(setting as Severity)) {
          warnings.push(`${configPath}: Invalid severity "${setting}" for rule "${ruleId}"`);
        }
        continue;
      }
      if (typeof setting === 'object' && setting !== null) {
        const ruleOpts = setting as Record<string, unknown>;
        if (ruleOpts['severity'] !== undefined && !Object.values(Severity).includes(ruleOpts['severity'] as Severity)) {
          warnings.push(`${configPath}: Invalid severity "${String(ruleOpts['severity'])}" for rule "${ruleId}"`);
        }
        continue;
      }
      warnings.push(`${configPath}: Invalid value for rule "${ruleId}" (expected boolean, severity string, or options object)`);
    }
  }

  return warnings;
}

export function loadConfig(cwd: string): ArhusConfig {
  const configPath = findConfigUp(cwd);

  if (configPath) {
    try {
      const raw = readFileSync(configPath, 'utf-8');
      const warnings = validateConfig(raw, configPath);
      for (const w of warnings) {
        console.error(`  ${w}`);
      }

      const user = JSON.parse(raw) as Partial<ArhusConfig>;

      return {
        include: user.include ?? defaults.include,
        exclude: user.exclude ?? defaults.exclude,
        rules: { ...defaults.rules, ...user.rules },
      };
    } catch {
      // fall through to defaults
    }
  }

  return defaults;
}
