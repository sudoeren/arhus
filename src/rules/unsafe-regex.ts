import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const NESTED_QUANTIFIER = /\([^)]*([+*])\).*\)\s*[+*]/;

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

    function walk(node: ts.Node) {
      if (ts.isRegularExpressionLiteral(node)) {
        const pattern = node.text.slice(1, node.text.lastIndexOf('/'));
        const msg = checkRegexPattern(pattern);
        if (msg) {
          const loc = getLocation(sourceFile, node.getStart(sourceFile));

          findings.push({
            ruleId: 'no-unsafe-regex',
            message: msg,
            severity: Severity.High,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + node.text.length,
          });
        }
      }

      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        let isRegexCall = false;

        if (ts.isIdentifier(callee) && callee.text === 'RegExp') {
          isRegexCall = true;
        } else if (ts.isPropertyAccessExpression(callee) &&
          callee.expression.kind === ts.SyntaxKind.RegExpKeyword &&
          callee.name.text === 'RegExp') {
          isRegexCall = true;
        } else if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'RegExp') {
          isRegexCall = true;
        }

        if (isRegexCall && node.arguments.length > 0 && ts.isStringLiteral(node.arguments[0])) {
          const pattern = node.arguments[0].text;
          const msg = checkRegexPattern(pattern);
          if (msg) {
            const loc = getLocation(sourceFile, node.arguments[0].getStart(sourceFile));

            findings.push({
              ruleId: 'no-unsafe-regex',
              message: msg,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + pattern.length + 2,
            });
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
