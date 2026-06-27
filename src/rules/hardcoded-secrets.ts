import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const SECRET_SUBSTRINGS = [
  'password', 'passwd', 'pwd', 'pass',
  'secret',
  'token',
  'apikey', 'api_key',
  'auth',
  'credential',
  'privatekey', 'private_key',
  'bearer',
];

const KNOWN_PREFIXES = [
  'sk-', 'sk_live_', 'sk_test_', 'rk_live_', 'rk_test_',
  'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_',
  'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-',
  'AKIA', 'ASIA',
  'eyJ',
  'SG.',
];

const MIN_ENTROPY_LENGTH = 20;

function isSuspiciousName(name: string): boolean {
  const lower = name.toLowerCase().replace(/[-_\s.]/g, '');
  return SECRET_SUBSTRINGS.some(s => lower.includes(s)) || lower === 'key';
}

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

function looksLikeSecret(value: string): string | null {
  if (value.length < 4) return null;

  for (const prefix of KNOWN_PREFIXES) {
    if (value.startsWith(prefix)) {
      return `String matches known secret prefix "${prefix}"`;
    }
  }

  if (value.length >= MIN_ENTROPY_LENGTH) {
    const charSet = new Set(value);
    if (charSet.size >= 10) {
      const upper = (value.match(/[A-Z]/g) ?? []).length;
      const lower = (value.match(/[a-z]/g) ?? []).length;
      const digits = (value.match(/[0-9]/g) ?? []).length;
      const specials = (value.match(/[^A-Za-z0-9]/g) ?? []).length;
      const entropy = upper + lower + digits + specials;
      if (entropy >= 20 && upper > 2 && lower > 2 && digits > 2) {
        return 'String matches high-entropy pattern, looks like a secret';
      }
    }
  }

  return null;
}

function getSuggestion(name: string): string {
  const envName = name.replace(/([A-Z])/g, '_$1').toUpperCase().replace(/^_/, '');
  return `process.env.${envName}`;
}

export const hardcodedSecretsRule: Rule = {
  id: 'no-hardcoded-secrets',
  name: 'No Hardcoded Secrets',
  description: 'Detects hardcoded API keys, tokens, and passwords in source code.',
  severity: Severity.Critical,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    function walk(node: ts.Node) {
      if (ts.isVariableDeclaration(node) && node.initializer && ts.isStringLiteral(node.initializer)) {
        const name = node.name.getText(context.sourceFile);
        const value = node.initializer.text;
        const secretMsg = looksLikeSecret(value);
        const isSuspicious = isSuspiciousName(name);

        if (isSuspicious || secretMsg) {
          const message = secretMsg ?? `Variable "${name}" is assigned a hardcoded string`;
          const severity = secretMsg && isSuspicious ? Severity.Critical : Severity.High;
          const loc = getLocation(context.sourceFile, node.initializer.getStart(context.sourceFile));

          findings.push({
            ruleId: 'no-hardcoded-secrets',
            message,
            severity,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + value.length + 2,
            suggestion: getSuggestion(name),
          });
        }
      }

      if (ts.isPropertyAssignment(node) && ts.isStringLiteral(node.initializer)) {
        const name = node.name.getText(context.sourceFile);
        const value = node.initializer.text;
        const secretMsg = looksLikeSecret(value);
        const isSuspicious = isSuspiciousName(name);

        if (isSuspicious || secretMsg) {
          const message = secretMsg ?? `Property "${name}" is assigned a hardcoded string`;
          const severity = secretMsg && isSuspicious ? Severity.Critical : Severity.High;
          const loc = getLocation(context.sourceFile, node.initializer.getStart(context.sourceFile));

          findings.push({
            ruleId: 'no-hardcoded-secrets',
            message,
            severity,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + value.length + 2,
            suggestion: getSuggestion(name),
          });
        }
      }

      if (ts.isStringLiteral(node)) {
        const parent = node.parent;
        if (ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent) || ts.isArrayLiteralExpression(parent)) {
          ts.forEachChild(node, walk);
          return;
        }

        const value = node.text;
        const secretMsg = looksLikeSecret(value);
        if (secretMsg) {
          const loc = getLocation(context.sourceFile, node.getStart(context.sourceFile));
          findings.push({
            ruleId: 'no-hardcoded-secrets',
            message: secretMsg,
            severity: Severity.High,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + value.length + 2,
          });
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(context.sourceFile);
    return findings;
  },
};
