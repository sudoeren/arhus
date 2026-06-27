import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { sqlInjectionRule } from '../../src/rules/sql-injection';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-sql-injection', () => {
  test('flags template literal with SQL and interpolation', () => {
    const ctx = makeContext('const q = `SELECT * FROM users WHERE name = \'${userName}\'`;');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('template literal');
  });

  test('flags string concatenation with SQL', () => {
    const ctx = makeContext('const q = "SELECT * FROM users WHERE id = " + userId;');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('concatenation');
  });

  test('flags SQL string concatenation in db query call', () => {
    const ctx = makeContext('db.query("SELECT * FROM users WHERE id = " + userId);');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('database method');
  });

  test('flags template literal SQL in db query call', () => {
    const ctx = makeContext('connection.execute(`UPDATE users SET name = \'${name}\' WHERE id = ${id}`);');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('template literal');
  });

  test('flags INSERT with concatenation', () => {
    const ctx = makeContext('const q = "INSERT INTO users VALUES (" + data + ")";');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('flags DELETE with concatenation', () => {
    const ctx = makeContext('db.run("DELETE FROM users WHERE id = " + request.params.id);');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('flags DROP TABLE concatenation', () => {
    const ctx = makeContext('const query = "DROP TABLE " + tableName;');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('does not flag parameterized queries', () => {
    const ctx = makeContext(`
      db.query("SELECT * FROM users WHERE id = ?", [userId]);
      db.query("SELECT * FROM users WHERE name = $1", [userName]);
    `);
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag template literals without SQL keywords', () => {
    const ctx = makeContext('const url = `https://api.example.com/users/${userId}`;');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag variable assignment without concatenation', () => {
    const ctx = makeContext('const q = "SELECT * FROM users";');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag Prisma ORM queries', () => {
    const ctx = makeContext(`
      const users = await prisma.user.findMany({ where: { name } });
    `);
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('flags raw() SQL with concatenation', () => {
    const ctx = makeContext('db.raw("SELECT * FROM users WHERE id = " + id);');
    const findings = sqlInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });
});
