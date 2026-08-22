import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

export const insecureCookiesRule: Rule = {
  id: 'no-insecure-cookies',
  name: 'No Insecure Cookies',
  description: 'Detects cookies without secure flags (httpOnly, secure, sameSite).',
  severity: Severity.Medium,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function checkCookieOptions(obj: ts.ObjectLiteralExpression, anchor: ts.Node) {
      const props = new Map<string, ts.PropertyAssignment>();
      for (const p of obj.properties) {
        if (ts.isPropertyAssignment(p)) {
          const n = p.name.getText(sourceFile).replace(/['"]/g, '');
          props.set(n, p);
        }
      }

      const httpOnly = props.get('httpOnly');
      const secure = props.get('secure');
      const sameSite = props.get('sameSite');

      if (!httpOnly || httpOnly.initializer.kind !== ts.SyntaxKind.TrueKeyword) {
        const span = httpOnly ? httpOnly.name.getStart(sourceFile) : anchor.getStart(sourceFile);
        const loc = getLocation(sourceFile, span);
        const msg = httpOnly ? 'Cookie with httpOnly:false is accessible via JavaScript' : 'Cookie without httpOnly flag is accessible via JavaScript';
        findings.push({
          ruleId: 'no-insecure-cookies',
          message: msg,
          severity: Severity.Medium,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + (httpOnly ? 8 : 6),
          suggestion: 'Set httpOnly:true to prevent XSS access to cookies',
        });
      }

      if (!secure || secure.initializer.kind !== ts.SyntaxKind.TrueKeyword) {
        const span = secure ? secure.name.getStart(sourceFile) : anchor.getStart(sourceFile);
        const loc = getLocation(sourceFile, span);
        const msg = secure ? 'Cookie with secure:false can be sent over HTTP' : 'Cookie without secure flag can be sent over HTTP';
        findings.push({
          ruleId: 'no-insecure-cookies',
          message: msg,
          severity: Severity.Medium,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + (secure ? 6 : 6),
          suggestion: 'Set secure:true to only send cookies over HTTPS',
        });
      }

      if (!sameSite) {
        const span = anchor.getStart(sourceFile);
        const loc = getLocation(sourceFile, span);
        findings.push({
          ruleId: 'no-insecure-cookies',
          message: 'Cookie without sameSite attribute is vulnerable to CSRF',
          severity: Severity.Medium,
          file: context.fileName,
          line: loc.line,
          column: loc.column,
          endLine: loc.line,
          endColumn: loc.column + 6,
          suggestion: 'Set sameSite to "strict" or "lax"',
        });
      } else {
        const v = sameSite.initializer;
        let isNone = false;
        if (ts.isStringLiteral(v) && v.text.toLowerCase() === 'none') isNone = true;
        if (isNone) {
          const span = sameSite.name.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);
          findings.push({
            ruleId: 'no-insecure-cookies',
            message: 'Cookie with sameSite:none requires secure:true and is CSRF-prone',
            severity: Severity.High,
            file: context.fileName,
            line: loc.line,
            column: loc.column,
            endLine: loc.line,
            endColumn: loc.column + 8,
            suggestion: 'Use sameSite:"strict" or "lax" instead of "none"',
          });
        }
      }
    }

    function walk(node: ts.Node) {
      // res.cookie(name, value, options)
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'cookie') {
        const args = node.arguments;
        if (args.length >= 3 && ts.isObjectLiteralExpression(args[2]!)) {
          checkCookieOptions(args[2] as ts.ObjectLiteralExpression, node.expression.name);
        } else if (args.length === 2 || args.length === 3) {
          // cookie without options at all
          const span = node.expression.name.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);
          const hasOptions = args.length === 3;
          if (!hasOptions) {
            findings.push({
              ruleId: 'no-insecure-cookies',
              message: 'Cookie set without secure options (httpOnly, secure, sameSite)',
              severity: Severity.Medium,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + 6,
              suggestion: 'Set { httpOnly:true, secure:true, sameSite:"strict" }',
            });
          } else {
            // has options but not object literal (dynamic) - still check if needed
          }
        }
      }

      // document.cookie = "...
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = node.left;
        if (ts.isPropertyAccessExpression(left) && left.name.text === 'cookie' && left.expression.getText(sourceFile) === 'document') {
          const span = left.name.getStart(sourceFile);
          const loc = getLocation(sourceFile, span);
          const rightText = node.right.getText(sourceFile).toLowerCase();
          const hasHttpOnly = rightText.includes('httponly');
          const hasSecure = rightText.includes('secure');
          const hasSameSite = rightText.includes('samesite');
          if (!hasHttpOnly || !hasSecure || !hasSameSite) {
            findings.push({
              ruleId: 'no-insecure-cookies',
              message: 'document.cookie set without secure flags',
              severity: Severity.Medium,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + 6,
              suggestion: 'Add HttpOnly, Secure, and SameSite attributes to cookie string',
            });
          }
        }
      }

      // res.setHeader('Set-Cookie', ...) - flag if no secure attributes in value
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'setHeader') {
        const firstArg = node.arguments[0];
        if (firstArg && ts.isStringLiteral(firstArg) && firstArg.text.toLowerCase() === 'set-cookie') {
          const secondArg = node.arguments[1];
          const valText = secondArg ? secondArg.getText(sourceFile).toLowerCase() : '';
          if (!valText.includes('httponly') || !valText.includes('secure') || !valText.includes('samesite')) {
            const span = node.expression.name.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);
            findings.push({
              ruleId: 'no-insecure-cookies',
              message: 'Set-Cookie header without secure flags',
              severity: Severity.Medium,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + 9,
              suggestion: 'Include HttpOnly, Secure, SameSite in Set-Cookie header',
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
