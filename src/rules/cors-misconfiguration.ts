import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const DANGEROUS_ORIGIN_PATTERNS = ['*', 'null', ''];

export const corsMisconfigurationRule: Rule = {
  id: 'no-cors-misconfiguration',
  name: 'No CORS Misconfiguration',
  description: 'Detects overly permissive CORS configurations.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isPropertyAssignment(node)) {
        const name = node.name.getText(sourceFile);

        if (name === 'Access-Control-Allow-Origin' || name === 'allowOrigin' || name === 'origin') {
          let value = '';
          let isWildcard = false;

          if (ts.isStringLiteral(node.initializer)) {
            value = node.initializer.text;
            isWildcard = DANGEROUS_ORIGIN_PATTERNS.includes(value);
          } else if (ts.isIdentifier(node.initializer)) {
            value = node.initializer.text;
            isWildcard = DANGEROUS_ORIGIN_PATTERNS.includes(value);
          }

          if (value === '*') {
            isWildcard = true;
          }

          if (isWildcard) {
            const span = node.initializer.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-cors-misconfiguration',
              message: `CORS set to "${value}" allows any origin to access the resource`,
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + (ts.isStringLiteral(node.initializer) ? value.length + 2 : value.length),
              suggestion: 'Restrict Access-Control-Allow-Origin to specific trusted origins',
            });
          }
        }

        if (name === 'credentials' || name === 'allowCredentials') {
          if (node.initializer.kind === ts.SyntaxKind.TrueKeyword) {
            const span = node.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-cors-misconfiguration',
              message: 'CORS credentials enabled with wildcard origin is insecure',
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + name.length,
              suggestion: 'Remove wildcard origin or disable credentials',
            });
          }
        }
      }

      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        if (node.expression.name.text === 'setHeader' && node.arguments.length >= 2 &&
            ts.isStringLiteral(node.arguments[0]!) &&
            node.arguments[0]!.text.toLowerCase() === 'access-control-allow-origin') {
          const secondArg = node.arguments[1]!;
          let isWildcard = false;

          if (ts.isStringLiteral(secondArg) && DANGEROUS_ORIGIN_PATTERNS.includes(secondArg.text)) {
            isWildcard = true;
          }

          if (isWildcard) {
            const span = secondArg.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-cors-misconfiguration',
              message: 'Access-Control-Allow-Origin set to wildcard, allows any origin',
              severity: Severity.High,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + (ts.isStringLiteral(secondArg) ? secondArg.text.length + 2 : 1),
              suggestion: 'Set specific allowed origins instead of wildcard',
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
