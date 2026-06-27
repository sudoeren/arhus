import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { unvalidatedRedirectRule } from '../../src/rules/unvalidated-redirect';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-unvalidated-redirect', () => {
  test('flags res.redirect with dynamic URL', () => {
    const ctx = makeContext('res.redirect(userInput);');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('redirect');
    expect(findings[0]!.message).toContain('open redirect');
  });

  test('flags res.redirect with concatenation', () => {
    const ctx = makeContext('res.redirect("/" + req.query.next);');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('flags window.location assignment', () => {
    const ctx = makeContext('window.location = userInput;');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('location');
  });

  test('flags location.href assignment', () => {
    const ctx = makeContext('location.href = "/redirect?to=" + url;');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('flags location.replace with dynamic URL', () => {
    const ctx = makeContext('window.location.replace(requestUrl);');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('does not flag static redirect', () => {
    const ctx = makeContext('res.redirect("/dashboard");');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag static location assignment', () => {
    const ctx = makeContext('window.location = "/home";');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('flags location.assign with dynamic URL', () => {
    const ctx = makeContext('location.assign(userInput);');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('does not flag non-redirect property assignments', () => {
    const ctx = makeContext('element.href = "/some/path";');
    const findings = unvalidatedRedirectRule.check(ctx);
    expect(findings.length).toBe(0);
  });
});
