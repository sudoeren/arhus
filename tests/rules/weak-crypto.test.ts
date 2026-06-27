import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { weakCryptoRule } from '../../src/rules/weak-crypto';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-weak-crypto', () => {
  test('flags createHash with MD5', () => {
    const ctx = makeContext("crypto.createHash('md5');");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('MD5');
  });

  test('flags createHash with SHA1', () => {
    const ctx = makeContext("crypto.createHash('sha1');");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('SHA-1');
  });

  test('flags createHmac with SHA1', () => {
    const ctx = makeContext("crypto.createHmac('sha1', key);");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('flags createCipheriv with DES', () => {
    const ctx = makeContext("crypto.createCipheriv('des-cbc', key, iv);");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('DES');
  });

  test('flags RC4', () => {
    const ctx = makeContext("crypto.createCipheriv('rc4', key, '');");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('RC4');
  });

  test('flags 3DES (detects DES)', () => {
    const ctx = makeContext("crypto.createCipheriv('des-ede3-cbc', key, iv);");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('DES');
  });

  test('does not flag SHA-256', () => {
    const ctx = makeContext("crypto.createHash('sha256');");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag AES-256-GCM', () => {
    const ctx = makeContext("crypto.createCipheriv('aes-256-gcm', key, iv);");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag non-crypto calls', () => {
    const ctx = makeContext("console.log('md5'); hashing('sha1');");
    const findings = weakCryptoRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('provides upgrade suggestion', () => {
    const ctx = makeContext("crypto.createHash('md5');");
    const findings = weakCryptoRule.check(ctx);
    expect(findings[0]!.suggestion).toContain('SHA-256');
  });
});
