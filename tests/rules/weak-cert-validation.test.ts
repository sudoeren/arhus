import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { weakCertValidationRule } from '../../src/rules/weak-cert-validation';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-weak-cert-validation', () => {
  test('flags rejectUnauthorized false', () => {
    const ctx = makeContext('const opts = { rejectUnauthorized: false };');
    expect(weakCertValidationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags rejectUnauthorized 0', () => {
    const ctx = makeContext('const opts = { rejectUnauthorized: "0" };');
    expect(weakCertValidationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags NODE_TLS_REJECT_UNAUTHORIZED', () => {
    const ctx = makeContext('const c = { NODE_TLS_REJECT_UNAUTHORIZED: false };');
    expect(weakCertValidationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags strictSSL false', () => {
    const ctx = makeContext('const c = { strictSSL: false };');
    expect(weakCertValidationRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag rejectUnauthorized true', () => {
    const ctx = makeContext('const opts = { rejectUnauthorized: true };');
    expect(weakCertValidationRule.check(ctx).length).toBe(0);
  });
  test('does not flag unrelated false', () => {
    const ctx = makeContext('const c = { enabled: false };');
    expect(weakCertValidationRule.check(ctx).length).toBe(0);
  });
});
