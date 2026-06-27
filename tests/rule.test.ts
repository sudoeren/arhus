import { describe, test, expect } from 'bun:test';
import { registerRule, getRule, getRules, clearRules } from '../src/rule';
import { Severity } from '../src/types';
import type { Rule } from '../src/types';

const dummyRule: Rule = {
  id: 'test-rule',
  name: 'Test Rule',
  description: 'A test rule',
  severity: Severity.Low,
  check: () => [],
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
