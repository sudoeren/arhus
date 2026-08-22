import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { prototypePollutionRule } from '../../src/rules/prototype-pollution';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-prototype-pollution', () => {
  test('flags Object.assign with dynamic arg', () => {
    const ctx = makeContext('Object.assign(target, userInput);');
    expect(prototypePollutionRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags _.merge with identifier', () => {
    const ctx = makeContext('_.merge({}, req.body);');
    expect(prototypePollutionRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags direct __proto__ assignment', () => {
    const ctx = makeContext('obj.__proto__.polluted = true;');
    const f = prototypePollutionRule.check(ctx);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]!.message).toContain('__proto__');
  });
  test('flags Object.fromEntries dynamic', () => {
    const ctx = makeContext('Object.fromEntries(userData);');
    expect(prototypePollutionRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag Object.assign with literal', () => {
    const ctx = makeContext('Object.assign({}, {a: 1});');
    expect(prototypePollutionRule.check(ctx).length).toBe(0);
  });
  test('does not flag safe property assignment', () => {
    const ctx = makeContext('obj.name = "value";');
    expect(prototypePollutionRule.check(ctx).length).toBe(0);
  });
});
