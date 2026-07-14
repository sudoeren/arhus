import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const REJECT_OPTIONS = new Set(['rejectUnauthorized', 'NODE_TLS_REJECT_UNAUTHORIZED']);
const DANGEROUS_OPTIONS = new Set(['strictSSL', 'allowUnauthorized', 'checkServerIdentity']);

export const weakCertValidationRule: Rule = {
  id: 'no-weak-cert-validation',
  name: 'No Weak Certificate Validation',
  description: 'Detects disabled TLS/SSL certificate validation.',
  severity: Severity.Critical,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isPropertyAssignment(node)) {
        const name = node.name.getText(sourceFile);

        if (REJECT_OPTIONS.has(name)) {
          if (node.initializer.kind === ts.SyntaxKind.FalseKeyword ||
              (ts.isStringLiteral(node.initializer) && node.initializer.text === '0')) {
            const span = node.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-weak-cert-validation',
              message: `"${name}" disabled — TLS certificate validation is turned off`,
              severity: Severity.Critical,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + name.length,
              suggestion: 'Remove or set to true to validate certificates',
            });
          }
        }

        if (DANGEROUS_OPTIONS.has(name)) {
          if (node.initializer.kind === ts.SyntaxKind.FalseKeyword ||
              node.initializer.kind === ts.SyntaxKind.NullKeyword) {
            const span = node.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);

            findings.push({
              ruleId: 'no-weak-cert-validation',
              message: `"${name}" is disabled/set to false, skipping security checks`,
              severity: Severity.Critical,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + name.length,
              suggestion: 'Remove or enable this security setting',
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
