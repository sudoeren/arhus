import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { pathTraversalRule } from '../../src/rules/path-traversal';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-path-traversal', () => {
  test('flags readFile with concatenated path', () => {
    const ctx = makeContext('readFile("/tmp/" + userInput);');
    const findings = pathTraversalRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('readFile');
    expect(findings[0]!.message).toContain('dynamic');
  });

  test('flags readFileSync with template literal', () => {
    const ctx = makeContext('readFileSync(`/data/${filename}`);');
    const findings = pathTraversalRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('flags writeFile with dynamic path', () => {
    const ctx = makeContext('writeFile(base + "/config.json", data);');
    const findings = pathTraversalRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.message).toContain('writeFile');
  });

  test('flags unlink with user input', () => {
    const ctx = makeContext('fs.unlink(userPath);');
    const findings = pathTraversalRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('flags createReadStream with dynamic path', () => {
    const ctx = makeContext('fs.createReadStream(path.join(dir, req.params.file));');
    const findings = pathTraversalRule.check(ctx);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('does not flag readFile with static path', () => {
    const ctx = makeContext('readFile("/etc/hosts");');
    const findings = pathTraversalRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag non-fs method calls', () => {
    const ctx = makeContext('console.log("/tmp/" + name);');
    const findings = pathTraversalRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('suggests path.resolve/normalize', () => {
    const ctx = makeContext('readFile(base + userInput);');
    const findings = pathTraversalRule.check(ctx);
    expect(findings[0]!.suggestion).toContain('path.resolve');
  });
});
