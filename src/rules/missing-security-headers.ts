import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

export const missingSecurityHeadersRule: Rule = {
  id: 'no-missing-security-headers',
  name: 'No Missing Security Headers',
  description: 'Detects missing security headers and helmet middleware.',
  severity: Severity.Medium,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;
    const sourceText = context.sourceText.toLowerCase();

    let expressInitNode: ts.Node | null = null;
    let hasHelmet = sourceText.includes('helmet');
    let hasSecurityHeaderSet = false;

    function walk(node: ts.Node) {
      // Detect express() initialization
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        let name = '';
        if (ts.isIdentifier(callee)) name = callee.text;
        else if (ts.isPropertyAccessExpression(callee)) name = callee.name.text;
        if (name === 'express' && !expressInitNode) {
          expressInitNode = node;
        }
      }

      // Detect app.use(helmet()) or helmet usage
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text.toLowerCase() === 'helmet') {
        hasHelmet = true;
      }
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const m = node.expression.name.text.toLowerCase();
        if (m === 'helmet') hasHelmet = true;
      }

      // Detect setHeader with security headers
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'setHeader') {
        const firstArg = node.arguments[0];
        if (firstArg && ts.isStringLiteral(firstArg)) {
          const h = firstArg.text.toLowerCase();
          if (
            h === 'x-frame-options' ||
            h === 'strict-transport-security' ||
            h === 'content-security-policy' ||
            h === 'x-content-type-options' ||
            h === 'referrer-policy' ||
            h === 'permissions-policy'
          ) {
            hasSecurityHeaderSet = true;
          }
        }
      }

      // Detect helmet import
      if (ts.isImportDeclaration(node)) {
        const mod = node.moduleSpecifier.getText(sourceFile).toLowerCase();
        if (mod.includes('helmet')) hasHelmet = true;
      }
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteral(arg) && arg.text.toLowerCase().includes('helmet')) hasHelmet = true;
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);

    if (expressInitNode && !hasHelmet && !hasSecurityHeaderSet) {
      const span = expressInitNode.getStart(sourceFile);
      const loc = getLocation(sourceFile, span);
      findings.push({
        ruleId: 'no-missing-security-headers',
        message: 'Express app without helmet or security headers',
        severity: Severity.Medium,
        file: context.fileName,
        line: loc.line,
        column: loc.column,
        endLine: loc.line,
        endColumn: loc.column + 7,
        suggestion: 'Use helmet() middleware or set X-Frame-Options, HSTS, CSP headers',
      });
    }

    return findings;
  },
};
