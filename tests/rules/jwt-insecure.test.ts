import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { jwtInsecureRule } from '../../src/rules/jwt-insecure';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-jwt-insecure', () => {
  test('flags hardcoded secret in sign', () => {
    const ctx = makeContext('jwt.sign(payload, "mysecret");');
    expect(jwtInsecureRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags none algorithm', () => {
    const ctx = makeContext('jwt.sign(payload, secret, {algorithm: "none"});');
    const f = jwtInsecureRule.check(ctx);
    expect(f.some(x=>x.message.includes("none"))).toBe(true);
  });
  test('flags verify with hardcoded secret', () => {
    const ctx = makeContext('jwt.verify(token, "hardcoded");');
    expect(jwtInsecureRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags decode without verify', () => {
    const ctx = makeContext('jwt.decode(token);');
    expect(jwtInsecureRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('flags ignoreExpiration', () => {
    const ctx = makeContext('jwt.verify(token, secret, {ignoreExpiration: true});');
    expect(jwtInsecureRule.check(ctx).some(f=>f.message.includes("ignoreExpiration"))).toBe(true);
  });
  test('does not flag secure usage', () => {
    const ctx = makeContext('jwt.sign(payload, process.env.JWT_SECRET, {algorithm: "HS256"});');
    expect(jwtInsecureRule.check(ctx).length).toBe(0);
  });
});
