import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

export const insecureRandomnessRule: Rule = {
  id: 'no-insecure-randomness',
  name: 'No Insecure Randomness',
  description: 'Detects usage of Math.random() for security-sensitive operations.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    const securityContexts = [
      'password', 'token', 'secret', 'key', 'salt', 'nonce',
      'otp', 'mfa', '2fa', 'verification', 'reset',
      'csrf', 'session', 'jwt', 'auth', 'crypto',
    ];

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node) &&
          ts.isPropertyAccessExpression(node.expression) &&
          node.expression.name.text === 'random' &&
          ts.isIdentifier(node.expression.expression) &&
          node.expression.expression.text === 'Math') {

        let inSecurityContext = false;
        let parent = node.parent;
        while (parent) {
          if (ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent) || ts.isBinaryExpression(parent)) {
            let nameText = '';
            if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
              nameText = parent.name.text;
            } else if (ts.isPropertyAssignment(parent)) {
              nameText = parent.name.getText(sourceFile);
            } else if (ts.isBinaryExpression(parent) && ts.isPropertyAccessExpression(parent.left)) {
              nameText = parent.left.name.text;
            }

            if (nameText && securityContexts.some(ctx => nameText.toLowerCase().includes(ctx))) {
              inSecurityContext = true;
              break;
            }
          }
          parent = parent.parent;
        }

        const span = node.expression.getStart(sourceFile);
        const loc = getLocation(sourceFile, span);

        findings.push({
          ruleId: 'no-insecure-randomness',
          message: `Math.random() used in${inSecurityContext ? ' security-sensitive' : ''} context, not cryptographically secure`,
          severity: inSecurityContext ? Severity.Critical : Severity.Medium,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + 11,
          suggestion: 'Use crypto.randomBytes() or crypto.randomInt() for secure random values',
        });
      }

      ts.forEachChild(node, walk);
    }

    walk(sourceFile);
    return findings;
  },
};
