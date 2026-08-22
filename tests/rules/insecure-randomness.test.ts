import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { insecureRandomnessRule } from '../../src/rules/insecure-randomness';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-insecure-randomness', () => {
  test('flags Math.random in security context', () => {
    const ctx = makeContext('const token = Math.random().toString();');
    const f = insecureRandomnessRule.check(ctx);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]!.severity).toBe('critical');
  });
  test('flags Math.random for password', () => {
    const ctx = makeContext('const password = Math.random();');
    expect(insecureRandomnessRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags Math.random generic', () => {
    const ctx = makeContext('const x = Math.random();');
    const f = insecureRandomnessRule.check(ctx);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]!.message).toContain('Math.random()');
  });
  test('does not flag crypto.randomBytes', () => {
    const ctx = makeContext('const t = crypto.randomBytes(32).toString("hex");');
    expect(insecureRandomnessRule.check(ctx).length).toBe(0);
  });
});
