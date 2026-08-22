import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { corsMisconfigurationRule } from '../../src/rules/cors-misconfiguration';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-cors-misconfiguration', () => {
  test('flags origin *', () => {
    const ctx = makeContext('const c = { origin: "*" };');
    expect(corsMisconfigurationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags Access-Control-Allow-Origin *', () => {
    const ctx = makeContext('const h = { "Access-Control-Allow-Origin": "*" };');
    expect(corsMisconfigurationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags credentials true', () => {
    const ctx = makeContext('const c = { credentials: true };');
    expect(corsMisconfigurationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags setHeader wildcard', () => {
    const ctx = makeContext('res.setHeader("Access-Control-Allow-Origin", "*");');
    expect(corsMisconfigurationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag specific origin', () => {
    const ctx = makeContext('const c = { origin: "https://example.com" };');
    expect(corsMisconfigurationRule.check(ctx).length).toBe(0);
  });
  test('does not flag credentials false', () => {
    const ctx = makeContext('const c = { credentials: false };');
    expect(corsMisconfigurationRule.check(ctx).length).toBe(0);
  });
});
