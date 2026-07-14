import { describe, test, expect } from 'bun:test';
import { loadConfig, validateConfig } from '../src/config';

describe('config', () => {
  test('loads defaults when no .arhusrc exists', () => {
    const config = loadConfig('/tmp/nonexistent');
    expect(config.include).toEqual(['**/*.{ts,tsx,js,jsx}']);
    expect(config.exclude).toContain('node_modules/**');
    expect(config.rules).toEqual({});
  });
});

describe('validateConfig', () => {
  test('returns no warnings for valid config', () => {
    const raw = JSON.stringify({
      include: ['**/*.ts'],
      exclude: ['node_modules'],
      rules: { 'no-console': false, 'no-debugger': 'high' },
    });
    const warnings = validateConfig(raw, '.arhusrc');
    expect(warnings).toHaveLength(0);
  });

  test('warns about unknown top-level keys', () => {
    const raw = JSON.stringify({ unknownKey: true, include: ['**/*.ts'] });
    const warnings = validateConfig(raw, '.arhusrc');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('unknownKey');
  });

  test('warns about invalid JSON', () => {
    const warnings = validateConfig('invalid json', '.arhusrc');
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0]).toContain('Invalid JSON');
  });

  test('warns about invalid rule severity string', () => {
    const raw = JSON.stringify({ rules: { 'no-console': 'super-critical' } });
    const warnings = validateConfig(raw, '.arhusrc');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('super-critical');
  });

  test('warns about invalid rule severity in object', () => {
    const raw = JSON.stringify({ rules: { 'no-console': { severity: 'ultra-high' } } });
    const warnings = validateConfig(raw, '.arhusrc');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('ultra-high');
  });

  test('warns about invalid rule value type', () => {
    const raw = JSON.stringify({ rules: { 'no-console': 42 } });
    const warnings = validateConfig(raw, '.arhusrc');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('Invalid value');
  });

  test('warns about include not being array', () => {
    const raw = JSON.stringify({ include: '**/*.ts' });
    const warnings = validateConfig(raw, '.arhusrc');
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('include');
  });
});
