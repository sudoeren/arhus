import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const MUTATING_METHODS = new Set(['post', 'put', 'patch', 'delete']);
const CSRF_TOKENS = new Set(['csrf', 'csurf', 'csrfprotection', 'csrftoken', 'xsrf']);

function isCsrfIdentifier(name: string): boolean {
  return CSRF_TOKENS.has(name.toLowerCase());
}

function hasCsrfInArgs(args: ts.NodeArray<ts.Expression>): boolean {
  for (const arg of args) {
    if (ts.isIdentifier(arg) && isCsrfIdentifier(arg.text)) return true;
    if (ts.isCallExpression(arg)) {
      const expr = arg.expression;
      const text = ts.isIdentifier(expr) ? expr.text : ts.isPropertyAccessExpression(expr) ? expr.name.text : '';
      if (isCsrfIdentifier(text)) return true;
      for (const inner of arg.arguments) {
        if (ts.isIdentifier(inner) && isCsrfIdentifier(inner.text)) return true;
      }
    }
    if (ts.isIdentifier(arg) && arg.text.toLowerCase().includes('csrf')) return true;
    const text = arg.getText();
    if (text.toLowerCase().includes('csrf')) return true;
  }
  return false;
}

export const csrfRule: Rule = {
  id: 'no-csrf',
  name: 'No Missing CSRF Protection',
  description: 'Detects state-changing routes without CSRF protection.',
  severity: Severity.Medium,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;
    const sourceText = context.sourceText.toLowerCase();
    const hasGlobalCsrf = sourceText.includes('csrf') || sourceText.includes('csurf');

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        if (MUTATING_METHODS.has(method)) {
          // Check if callee object looks like app/router/server
          const obj = node.expression.expression;
          const objText = obj.getText(sourceFile).toLowerCase();
          const isRouteHandler =
            objText === 'app' ||
            objText === 'router' ||
            objText.endsWith('router') ||
            objText.endsWith('app') ||
            method.length > 0; // fallback: any post/put/patch/delete call is suspicious

          if (isRouteHandler && node.arguments.length >= 1) {
            // If global csrf not present at all, flag directly
            // If global csrf present, check per-route args
            const hasCsrfArg = hasCsrfInArgs(node.arguments);
            if (!hasCsrfArg && !hasGlobalCsrf) {
              const span = node.expression.name.getStart(sourceFile);
              const loc = getLocation(sourceFile, span);
              findings.push({
                ruleId: 'no-csrf',
                message: `State-changing route "${method}" without CSRF protection`,
                severity: Severity.Medium,
                file: context.fileName,
                line: loc.line,
                column: loc.column,
                endLine: loc.line,
                endColumn: loc.column + method.length,
                suggestion: 'Add CSRF middleware (e.g., csurf, csrf-csrf) to this route',
              });
            } else if (hasGlobalCsrf && !hasCsrfArg) {
              // Global csrf exists but not applied to this route - still warn but less strict
              // Only flag if route has no middleware at all (single handler)
              if (node.arguments.length === 2 && ts.isStringLiteral(node.arguments[0]!)) {
                // 2 args: path + handler, no middleware - likely missing
                const span = node.expression.name.getStart(sourceFile);
                const loc = getLocation(sourceFile, span);
                findings.push({
                  ruleId: 'no-csrf',
                  message: `State-changing route "${method}" may be missing CSRF middleware`,
                  severity: Severity.Medium,
                  file: context.fileName,
                  line: loc.line,
                  column: loc.column,
                  endLine: loc.line,
                  endColumn: loc.column + method.length,
                  suggestion: 'Ensure CSRF protection is applied to this route',
                });
              }
            }
          }
        }
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
