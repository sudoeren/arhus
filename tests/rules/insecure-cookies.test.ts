import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { insecureCookiesRule } from '../../src/rules/insecure-cookies';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-insecure-cookies', () => {
  test('flags cookie without options', () => {
    const ctx = makeContext('res.cookie("session", "abc");');
    expect(insecureCookiesRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags httpOnly false', () => {
    const ctx = makeContext('res.cookie("a","b",{httpOnly:false, secure:true, sameSite:"lax"});');
    expect(insecureCookiesRule.check(ctx).some(f=>f.message.includes("httpOnly"))).toBe(true);
  });
  test('flags missing secure', () => {
    const ctx = makeContext('res.cookie("a","b",{httpOnly:true, sameSite:"strict"});');
    expect(insecureCookiesRule.check(ctx).some(f=>f.message.includes("secure"))).toBe(true);
  });
  test('flags document.cookie without flags', () => {
    const ctx = makeContext('document.cookie = "session=abc";');
    expect(insecureCookiesRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag secure cookie', () => {
    const ctx = makeContext('res.cookie("a","b",{httpOnly:true, secure:true, sameSite:"strict"});');
    expect(insecureCookiesRule.check(ctx).length).toBe(0);
  });
  test('flags sameSite none', () => {
    const ctx = makeContext('res.cookie("a","b",{httpOnly:true, secure:true, sameSite:"none"});');
    expect(insecureCookiesRule.check(ctx).some(f=>f.message.includes("sameSite:none"))).toBe(true);
  });
});
