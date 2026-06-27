import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { commandInjectionRule } from '../../src/rules/command-injection';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-command-injection', () => {
  test('flags exec() with concatenated command', () => {
    const ctx = makeContext('exec("ls -la " + userDir);');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('exec');
    expect(findings[0]!.message).toContain('dynamically');
  });

  test('flags execSync() with template literal', () => {
    const ctx = makeContext('execSync(`ping ${hostname}`);');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('execSync');
  });

  test('flags spawn() with shell:true', () => {
    const ctx = makeContext('spawn("ls", ["-la"], { shell: true });');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('shell:true');
  });

  test('flags spawnSync() with shell:true', () => {
    const ctx = makeContext('spawnSync("sh", ["-c", untrusted], { shell: true });');
    const findings = commandInjectionRule.check(ctx);
    const shellFindings = findings.filter(f => f.message.includes('shell:true'));
    expect(shellFindings.length).toBeGreaterThan(0);
  });

  test('flags execFile() with concatenated args', () => {
    const ctx = makeContext('execFile("cmd" + userInput + ".exe");');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('execFile');
  });

  test('does not flag exec() with static string', () => {
    const ctx = makeContext('exec("ls -la /tmp");');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag spawn() with args array (safe)', () => {
    const ctx = makeContext('spawn("ls", [userDir]);');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag execSync() with static string', () => {
    const ctx = makeContext('execSync("node --version");');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag safe method.call pattern', () => {
    const ctx = makeContext('cp.execFile("safe", ["arg1"]);');
    const findings = commandInjectionRule.check(ctx);
    expect(findings.length).toBe(0);
  });
});
