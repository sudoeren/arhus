import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';
import { getLocation } from '../utils';

const JWT_METHODS = new Set(['sign', 'verify', 'decode']);

function isJwtCallee(node: ts.CallExpression, sourceFile: ts.SourceFile): string | null {
  const expr = node.expression;
  if (ts.isPropertyAccessExpression(expr)) {
    const method = expr.name.text;
    if (JWT_METHODS.has(method)) {
      const obj = expr.expression.getText(sourceFile).toLowerCase();
      if (obj.includes('jwt') || obj.includes('jsonwebtoken') || obj.includes('jose')) {
        return method;
      }
      // also handle imported as `import jwt from 'jsonwebtoken'` -> obj is jwt
      if (obj === 'jwt' || obj === 'jose' || obj === 'token') return method;
    }
  }
  if (ts.isIdentifier(expr) && JWT_METHODS.has(expr.text)) {
    return expr.text;
  }
  return null;
}

function hasNoneAlg(options: ts.Expression | undefined, sourceFile: ts.SourceFile): boolean {
  if (!options || !ts.isObjectLiteralExpression(options)) return false;
  for (const prop of options.properties) {
    if (ts.isPropertyAssignment(prop)) {
      const name = prop.name.getText(sourceFile).replace(/['"]/g, '');
      if (name === 'algorithm' || name === 'alg' || name === 'algorithms') {
        const init = prop.initializer;
        if (ts.isStringLiteral(init) && init.text.toLowerCase() === 'none') return true;
        if (ts.isArrayLiteralExpression(init)) {
          for (const el of init.elements) {
            if (ts.isStringLiteral(el) && el.text.toLowerCase() === 'none') return true;
          }
        }
      }
      if (name === 'ignoreExpiration' && init.kind === ts.SyntaxKind.TrueKeyword) return true;
    }
  }
  return false;
}

export const jwtInsecureRule: Rule = {
  id: 'no-jwt-insecure',
  name: 'No Insecure JWT',
  description: 'Detects insecure JWT usage including none algorithm and hardcoded secrets.',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        const method = isJwtCallee(node, sourceFile);
        if (method) {
          const args = node.arguments;

          // Check for hardcoded secret (second arg is string literal)
          if ((method === 'sign' || method === 'verify') && args.length >= 2) {
            const secretArg = args[1]!;
            if (ts.isStringLiteral(secretArg) && secretArg.text.length > 0) {
              // Flag hardcoded secrets shorter than 32 or any literal that is not env
              const span = secretArg.getStart(sourceFile);
              const loc = getLocation(sourceFile, span);
              findings.push({
                ruleId: 'no-jwt-insecure',
                message: `JWT ${method}() with hardcoded secret "${secretArg.text.slice(0, 10)}..."`,
                severity: Severity.High,
                file: context.fileName,
                line: loc.line,
                column: loc.column,
                endLine: loc.line,
                endColumn: loc.column + secretArg.text.length + 2,
                suggestion: 'Use a strong secret from environment variables (process.env.JWT_SECRET)',
              });
            }

            // Check for none algorithm in options (3rd arg)
            if (args.length >= 3) {
              const options = args[2]!;
              let isNone = false;
              let offendingProp: ts.Node | null = null;
              if (ts.isObjectLiteralExpression(options)) {
                for (const prop of options.properties) {
                  if (ts.isPropertyAssignment(prop)) {
                    const name = prop.name.getText(sourceFile).replace(/['"]/g, '');
                    const init = prop.initializer;
                    if ((name === 'algorithm' || name === 'alg') && ts.isStringLiteral(init) && init.text.toLowerCase() === 'none') {
                      isNone = true;
                      offendingProp = prop.name;
                    }
                    if (name === 'algorithms' && ts.isArrayLiteralExpression(init)) {
                      for (const el of init.elements) {
                        if (ts.isStringLiteral(el) && el.text.toLowerCase() === 'none') {
                          isNone = true;
                          offendingProp = prop.name;
                        }
                      }
                    }
                  }
                }
              }
              if (isNone && offendingProp) {
                const span = offendingProp.getStart(sourceFile);
                const loc = getLocation(sourceFile, span);
                findings.push({
                  ruleId: 'no-jwt-insecure',
                  message: `JWT ${method}() uses "none" algorithm, bypasses signature verification`,
                  severity: Severity.Critical,
                  file: context.fileName,
                  line: loc.line,
                  column: loc.column,
                  endLine: loc.line,
                  endColumn: loc.column + 9,
                  suggestion: 'Remove none algorithm, use RS256 or HS256 with verification',
                });
              }

              // Check ignoreExpiration
              if (ts.isObjectLiteralExpression(options)) {
                for (const prop of options.properties) {
                  if (ts.isPropertyAssignment(prop) && prop.name.getText(sourceFile).replace(/['"]/g, '') === 'ignoreExpiration' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) {
                    const span = prop.name.getStart(sourceFile);
                    const loc = getLocation(sourceFile, span);
                    findings.push({
                      ruleId: 'no-jwt-insecure',
                      message: `JWT ${method}() with ignoreExpiration:true skips expiry validation`,
                      severity: Severity.High,
                      file: context.fileName,
                      line: loc.line,
                      column: loc.column,
                      endLine: loc.line,
                      endColumn: loc.column + 16,
                      suggestion: 'Remove ignoreExpiration or handle expiry explicitly',
                    });
                  }
                }
              }
            }
          }

          // Decode without verify is risky
          if (method === 'decode' && args.length >= 1) {
            const span = ts.isPropertyAccessExpression(node.expression)
              ? node.expression.name.getStart(sourceFile)
              : node.expression.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);
            findings.push({
              ruleId: 'no-jwt-insecure',
              message: 'jwt.decode() does not verify signature, use jwt.verify() instead',
              severity: Severity.Medium,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + method.length,
              suggestion: 'Use jwt.verify() to validate signature before trusting payload',
            });
          }

          // Direct none literal in any arg: jwt.sign(payload, secret, {algorithm: "none"})
          // Already handled above, but also check string literal "none" alone in sign/verify
          for (const arg of args) {
            if (ts.isObjectLiteralExpression(arg) && hasNoneAlg(arg, sourceFile)) {
              // already reported as critical above - avoid duplicate
              if (method !== 'decode') {
                const already = findings.some(f => f.message.includes('none') && f.line === getLocation(sourceFile, arg.getStart(sourceFile)).line);
                if (!already) {
                  const span = arg.getStart(sourceFile);
                  const loc = getLocation(sourceFile, span);
                  findings.push({
                    ruleId: 'no-jwt-insecure',
                    message: `JWT ${method}() configured with insecure "none" algorithm`,
                    severity: Severity.Critical,
                    file: context.fileName,
                    line: loc.line,
                    column: loc.column,
                    endLine: loc.line,
                    endColumn: loc.column + 4,
                    suggestion: 'Use a secure algorithm like HS256 or RS256',
                  });
                }
              }
            }
          }
        }
      }

      // Also detect object literal { alg: "none" } directly assigned (e.g., header)
      if (ts.isPropertyAssignment(node)) {
        const name = node.name.getText(sourceFile).replace(/['"]/g, '');
        if ((name === 'alg' || name === 'algorithm') && ts.isStringLiteral(node.initializer) && node.initializer.text.toLowerCase() === 'none') {
          // Check parent is JWT-related object
          const parentText = node.parent.getText(sourceFile).toLowerCase();
          if (parentText.includes('jwt') || parentText.includes('header') || parentText.includes('sign') || parentText.includes('verify')) {
            const span = node.initializer.getStart(sourceFile);
            const loc = getLocation(sourceFile, span);
            findings.push({
              ruleId: 'no-jwt-insecure',
              message: 'JWT header with "none" algorithm disables verification',
              severity: Severity.Critical,
              file: context.fileName,
              line: loc.line,
              column: loc.column,
              endLine: loc.line,
              endColumn: loc.column + 6,
              suggestion: 'Use a secure signing algorithm',
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
