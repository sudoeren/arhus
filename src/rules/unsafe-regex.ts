import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const NESTED_QUANTIFIER = /\([^)]*[+*][^)]*\)\s*[+*]/;
const EVIL_PATTERNS: { pattern: RegExp; message: string }[] = [
  { pattern: /\([^)]*\+(?:[^)]*\+[^)]*)+\)/, message: 'Regex has nested quantifiers with multiple +, vulnerable to ReDoS attacks' },
  { pattern: /\([^)]*\*(?:[^)]*\*[^)]*)+\)/, message: 'Regex has nested quantifiers with multiple *, vulnerable to ReDoS attacks' },
  { pattern: /\(\.[+*]\)[+*]/, message: 'Regex has possessive quantifier on wildcard, vulnerable to ReDoS' },
  { pattern: /\(.[+*]\)\{/, message: 'Regex has quantified group with quantifier, vulnerable to ReDoS' },
  { pattern: /\(S.\|[^)]+\)\+/, message: 'Regex has repeating alternation group, consider ReDoS risk' },
];

function checkRegexPattern(pattern: string): string | null {
  for (const { pattern: re, message } of EVIL_PATTERNS) {
    if (re.test(pattern)) {
      return message;
    }
  }

  if (NESTED_QUANTIFIER.test(pattern)) {
    return 'Regex has nested quantifiers, vulnerable to ReDoS attacks';
  }

  const alts = pattern.split('|');
  for (let i = 0; i < alts.length; i++) {
    for (let j = i + 1; j < alts.length; j++) {
      const a = alts[i]!.replace(/[\\^$.|?*+()[\]]/g, '');
      const b = alts[j]!.replace(/[\\^$.|?*+()[\]]/g, '');
      if (a.length > 0 && b.length > 0 && (a.startsWith(b) || b.startsWith(a))) {
        return 'Regex has overlapping alternation, potentially vulnerable to ReDoS';
      }
    }
  }

  const matches = pattern.match(/\([^)]+\)/g);
  if (matches) {
    for (let i = 0; i < matches.length; i++) {
      for (let j = i + 1; j < matches.length; j++) {
        const cleanA = matches[i]!.replace(/[+*?{}()]/g, '');
        const cleanB = matches[j]!.replace(/[+*?{}()]/g, '');
        if (cleanA.length > 3 && cleanA === cleanB) {
          return 'Regex has duplicate groups, potentially causing polynomial backtracking';
        }
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
        const args = node.arguments;

        if (args && args.length > 0 && ts.isIdentifier(callee) && callee.text === 'RegExp') {
          const firstArg = args[0];
          if (firstArg && ts.isStringLiteral(firstArg)) {
            pushFinding(firstArg.text, firstArg.getStart(sourceFile), firstArg.getEnd());
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
