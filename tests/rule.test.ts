import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { registerRule, getRule, getRules, getActiveRules, clearRules } from '../src/rule';
import { Severity } from '../src/types';
import type { Rule, ArhusConfig } from '../src/types';

const defaultConfig: ArhusConfig = {
  include: ['**/*.ts'],
  exclude: [],
  rules: {},
};

const dummyRule: Rule = {
  id: 'test-rule',
  name: 'Test Rule',
  description: 'A test rule',
  severity: Severity.Low,
  check: () => [{ ruleId: 'test-rule', message: 'test', severity: Severity.Low, file: 'test.ts', line: 1, column: 1 }],
};

const criticalRule: Rule = {
  id: 'critical-rule',
  name: 'Critical Rule',
  description: 'A critical test rule',
  severity: Severity.Critical,
  check: () => [{ ruleId: 'critical-rule', message: 'test', severity: Severity.Critical, file: 'test.ts', line: 1, column: 1 }],
};

describe('rule registry', () => {
  test('registers and retrieves rules', () => {
    clearRules();
    registerRule(dummyRule);
    expect(getRule('test-rule')).toBe(dummyRule);
    expect(getRules()).toHaveLength(1);
  });

  test('throws on duplicate registration', () => {
    clearRules();
    registerRule(dummyRule);
    expect(() => registerRule(dummyRule)).toThrow();
  });
});

describe('getActiveRules', () => {
  test('returns all rules with empty config', () => {
    clearRules();
    registerRule(dummyRule);
    registerRule(criticalRule);
    const active = getActiveRules(defaultConfig);
    expect(active).toHaveLength(2);
  });

  test('filters out rules set to false', () => {
    clearRules();
    registerRule(dummyRule);
    registerRule(criticalRule);
    const config: ArhusConfig = { ...defaultConfig, rules: { 'test-rule': false } };
    const active = getActiveRules(config);
    expect(active).toHaveLength(1);
    expect(active[0]!.id).toBe('critical-rule');
  });

  test('filters out multiple disabled rules', () => {
    clearRules();
    registerRule(dummyRule);
    registerRule(criticalRule);
    const config: ArhusConfig = { ...defaultConfig, rules: { 'test-rule': false, 'critical-rule': false } };
    const active = getActiveRules(config);
    expect(active).toHaveLength(0);
  });

  test('overrides severity via string shorthand', () => {
    clearRules();
    registerRule(dummyRule);
    const config: ArhusConfig = { ...defaultConfig, rules: { 'test-rule': Severity.High } };
    const active = getActiveRules(config);
    expect(active[0]!.severity).toBe(Severity.High);
  });

  test('overrides severity via object', () => {
    clearRules();
    registerRule(dummyRule);
    const config: ArhusConfig = { ...defaultConfig, rules: { 'test-rule': { severity: Severity.Critical } } };
    const active = getActiveRules(config);
    expect(active[0]!.severity).toBe(Severity.Critical);
  });

  test('overridden severity applies to findings', () => {
    clearRules();
    registerRule(dummyRule);
    const config: ArhusConfig = { ...defaultConfig, rules: { 'test-rule': Severity.Critical } };
    const active = getActiveRules(config);
    const sourceFile = ts.createSourceFile('test.ts', '', ts.ScriptTarget.Latest, true);
    const findings = active[0]!.check({ fileName: 'test.ts', sourceText: '', sourceFile });
    expect(findings[0]!.severity).toBe(Severity.Critical);
  });

  test('does not override severity when not configured', () => {
    clearRules();
    registerRule(dummyRule);
    const active = getActiveRules(defaultConfig);
    expect(active[0]!.severity).toBe(Severity.Low);
  });
});

