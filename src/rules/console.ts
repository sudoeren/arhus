import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const CONSOLE_METHODS = new Set(['log', 'error', 'warn', 'info', 'debug', 'table', 'trace', 'dir', 'assert', 'count', 'time', 'timeEnd']);

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

export const consoleRule: Rule = {
  id: 'no-console',
  name: 'No Console',
  description: 'Detects console.log and other console statements in production code.',
  severity: Severity.Info,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const callee = node.expression;
        if (ts.isIdentifier(callee.expression) && callee.expression.text === 'console') {
          if (CONSOLE_METHODS.has(callee.name.text)) {
            const span = callee.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-console',
              message: `console.${callee.name.text}() found, consider removing in production`,
              severity: Severity.Info,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + callee.name.text.length,
              suggestion: 'Use a proper logging library or remove before deployment',
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
