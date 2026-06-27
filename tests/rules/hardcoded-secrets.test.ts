import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { hardcodedSecretsRule } from '../../src/rules/hardcoded-secrets';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return {
    fileName: 'test.ts',
    sourceText: code,
    sourceFile,
  };
}

describe('no-hardcoded-secrets', () => {
  test('flags variable with suspicious name assigned to string', () => {
    const ctx = makeContext('const apiKey = "secret123value";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.ruleId).toBe('no-hardcoded-secrets');
    expect(findings[0]!.message).toContain('apiKey');
    expect(findings[0]!.suggestion).toBe('process.env.API_KEY');
  });

  test('flags property with suspicious name assigned to string', () => {
    const ctx = makeContext('const config = { password: "admin123!" };');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('password');
  });

  test('flags known API key prefix (sk-)', () => {
    const ctx = makeContext('const key = "sk-live-abc123def456ghi789jkl012mno345pqr678stu901vwx";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('sk-');
  });

  test('flags known GitHub token prefix (ghp_)', () => {
    const ctx = makeContext('const token = "ghp_abc123def456ghi789jkl012mno345";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('ghp_');
  });

  test('flags high-entropy string in standalone context', () => {
    const ctx = makeContext('const data = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('high-entropy');
  });

  test('does not flag normal short strings', () => {
    const ctx = makeContext('const name = "John"; const city = "Istanbul";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag non-suspicious variable names', () => {
    const ctx = makeContext('const url = "https://example.com";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag process.env usage', () => {
    const ctx = makeContext('const apiKey = process.env.API_KEY;');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('detects secret in object spread context', () => {
    const ctx = makeContext(`
      const db = {
        host: "localhost",
        password: "supersecret1234!@#$!@#$"
      };
    `);
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('password');
  });

  test('flags Slack token prefix (xoxb-)', () => {
    const ctx = makeContext('const slackToken = "xoxb-1234567890-abcdefghijklmnop";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('xoxb-');
  });

  test('flags AWS key prefix (AKIA)', () => {
    const ctx = makeContext('const awsKey = "AKIAIOSFODNN7EXAMPLE";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('AKIA');
  });

  test('flags JWT token (eyJ prefix)', () => {
    const ctx = makeContext('const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('eyJ');
  });

  test('suggestion converts camelCase to UPPER_SNAKE_CASE', () => {
    const ctx = makeContext('const dbPassword = "mypass123";');
    const findings = hardcodedSecretsRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.suggestion).toBe('process.env.DB_PASSWORD');
  });
});
