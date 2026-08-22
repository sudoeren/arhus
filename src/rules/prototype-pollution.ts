import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const DANGEROUS_MERGE_METHODS = new Set([
  'assign',
  'merge',
  'extend',
  'deepMerge',
  'deepmerge',
  'mergeDeep',
]);

export const prototypePollutionRule: Rule = {
  id: 'no-prototype-pollution',
  name: 'No Prototype Pollution',
  description: 'Detects unsafe object merge/assign operations that can lead to prototype pollution.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        let calleeText = '';

        if (ts.isPropertyAccessExpression(callee)) {
          calleeText = callee.name.text;
        } else if (ts.isIdentifier(callee)) {
          calleeText = callee.text;
        }

        if (calleeText && DANGEROUS_MERGE_METHODS.has(calleeText)) {
          const hasDynamicTarget = node.arguments.some(a =>
            ts.isIdentifier(a) ||
            ts.isCallExpression(a) ||
            ts.isPropertyAccessExpression(a)
          );

          if (hasDynamicTarget) {
            const span = callee.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-prototype-pollution',
              message: `"${calleeText}()" can cause prototype pollution if merging untrusted objects`,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + calleeText.length,
              suggestion: 'Use Object.create(null) for maps, or validate keys against "__proto__", "constructor", "prototype"',
            });
          }
        }

        if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'fromEntries' && ts.isIdentifier(callee.expression)) {
          if (callee.expression.text === 'Object' && node.arguments.length > 0) {
            const span = callee.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-prototype-pollution',
              message: 'Dynamic key assignment with Object.fromEntries() can lead to prototype pollution',
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + 4,
              suggestion: 'Use a Map or Object.create(null) instead',
            });
          }
        }
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const leftText = node.left.getText(sourceFile);
        if (leftText.includes('__proto__') || leftText.includes('.prototype')) {
          // Find the offending segment
          let propName = '__proto__';
          if (leftText.includes('prototype')) propName = 'prototype';
          const span = node.left.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);
          findings.push({
            ruleId: 'no-prototype-pollution',
            message: `Direct assignment to "${propName}" is a prototype pollution vector`,
            severity: Severity.Critical,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + propName.length,
          });
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
