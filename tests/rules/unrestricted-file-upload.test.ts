import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { unrestrictedFileUploadRule } from '../../src/rules/unrestricted-file-upload';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-unrestricted-file-upload', () => {
  test('flags mv() with dynamic path', () => {
    const ctx = makeContext('req.files.avatar.mv(uploadPath);');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('mv()');
  });

  test('flags mv() with concatenated path', () => {
    const ctx = makeContext('file.mv("/uploads/" + req.body.name);');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('flags writeFile with dynamic path (upload context)', () => {
    const ctx = makeContext('fs.writeFile(req.file.originalname, buffer);');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('writeFile');
  });

  test('flags createWriteStream with dynamic path', () => {
    const ctx = makeContext('fs.createWriteStream(userInput + ".pdf");');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(1);
  });

  test('does not flag mv() with static path', () => {
    const ctx = makeContext('file.mv("/uploads/avatar.png");');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag writeFile with static path', () => {
    const ctx = makeContext('fs.writeFile("/tmp/output.json", data);');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('does not flag non-file operations', () => {
    const ctx = makeContext('console.log(userInput); obj.mv();');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(0);
  });

  test('flags writeFileSync with dynamic path', () => {
    const ctx = makeContext('fs.writeFileSync(req.body.filename, content);');
    const findings = unrestrictedFileUploadRule.check(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0]!.message).toContain('writeFileSync');
  });
});
