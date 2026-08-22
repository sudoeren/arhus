import { describe, test, expect } from 'bun:test';
import ts from 'typescript';
import { missingSecurityHeadersRule } from '../../src/rules/missing-security-headers';
import type { RuleContext } from '../../src/types';

function makeContext(code: string): RuleContext {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  return { fileName: 'test.ts', sourceText: code, sourceFile };
}

describe('no-missing-security-headers', () => {
  test('flags express without helmet', () => {
    const ctx = makeContext('const app = express(); app.get("/", handler);');
    expect(missingSecurityHeadersRule.check(ctx).length).toBeGreaterThan(0);
  });
  test('does not flag with helmet import', () => {
    const ctx = makeContext('import helmet from "helmet"; const app = express(); app.use(helmet());');
    expect(missingSecurityHeadersRule.check(ctx).length).toBe(0);
  });
  test('does not flag with require helmet', () => {
    const ctx = makeContext('const helmet = require("helmet"); const app = express(); app.use(helmet());');
    expect(missingSecurityHeadersRule.check(ctx).length).toBe(0);
  });
  test('does not flag without express', () => {
    const ctx = makeContext('const x = 1;');
    expect(missingSecurityHeadersRule.check(ctx).length).toBe(0);
  });
  test('does not flag with security header set', () => {
    const ctx = makeContext('const app = express(); res.setHeader("X-Frame-Options", "DENY");');
    expect(missingSecurityHeadersRule.check(ctx).length).toBe(0);
  });
});
