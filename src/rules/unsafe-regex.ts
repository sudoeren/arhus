import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const NESTED_QUANTIFIER = /\([^)]*[+*][^)]*\)\s*[+*]/;

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

function checkRegexPattern(pattern: string): string | null {
  if (NESTED_QUANTIFIER.test(pattern)) {
    return 'Regex has nested quantifiers, vulnerable to ReDoS attacks';
  }

  const alts = pattern.split('|');
  for (let i = 0; i < alts.length; i++) {
    for (let j = i + 1; j < alts.length; j++) {
      if (alts[i]!.startsWith(alts[j]!) || alts[j]!.startsWith(alts[i]!)) {
        return 'Regex has overlapping alternation, potentially vulnerable to ReDoS';
      }
    }
  }

  return null;
}

export const unsafeRegexRule: Rule = {
  id: 'no-unsafe-regex',
  name: 'No Unsafe Regex',
  description: 'Detects regular expressions vulnerable to ReDoS attacks.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function pushFinding(pattern: string, start: number, end: number) {
      const msg = checkRegexPattern(pattern);
      if (!msg) return;

      const loc = getLocation(sourceFile, start);

      findings.push({
        ruleId: 'no-unsafe-regex',
        message: msg,
        severity: Severity.High,
        file: context.fileName,
        line: loc.line,
        column: loc.column,
        endLine: loc.line,
        endColumn: loc.column + (end - start),
      });
    }

    function walk(node: ts.Node) {
      if (ts.isRegularExpressionLiteral(node)) {
        const pattern = node.text.slice(1, node.text.lastIndexOf('/'));
        pushFinding(pattern, node.getStart(sourceFile), node.getEnd());
      }

      if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
        const callee = ts.isCallExpression(node) ? node.expression : node.expression;

        if (ts.isIdentifier(callee) && callee.text === 'RegExp' && node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0])) {
          const arg = node.arguments[0];
          pushFinding(arg.text, arg.getStart(sourceFile), arg.getEnd());
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
