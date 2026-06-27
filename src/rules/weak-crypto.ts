import ts from 'typescript';
import { Severity } from '../types';
import type { Rule, RuleContext, Finding } from '../types';

const WEAK_ALGOS: [string, string][] = [
  ['3des', '3DES'],
  ['md5', 'MD5'],
  ['md4', 'MD4'],
  ['sha1', 'SHA-1'],
  ['sha-1', 'SHA-1'],
  ['des', 'DES'],
  ['rc4', 'RC4'],
  ['ripemd', 'RIPEMD'],
];

const CRYPTO_METHODS = new Set([
  'createHash',
  'createHmac',
  'createCipheriv',
  'createDecipheriv',
  'createCipher',
  'createDecipher',
]);

function getLocation(sourceFile: ts.SourceFile, pos: number) {
  const { line, character } = ts.getLineAndCharacterOfPosition(sourceFile, pos);
  return { line: line + 1, column: character + 1 };
}

export const weakCryptoRule: Rule = {
  id: 'no-weak-crypto',
  name: 'No Weak Cryptography',
  description: 'Detects usage of weak cryptographic algorithms (MD5, SHA1, DES, RC4).',
  severity: Severity.High,
  check(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const sourceFile = context.sourceFile;

    function walk(node: ts.Node) {
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        if (!ts.isPropertyAccessExpression(callee)) {
          ts.forEachChild(node, walk);
          return;
        }

        if (CRYPTO_METHODS.has(callee.name.text) && node.arguments.length > 0) {
          const firstArg = node.arguments[0]!;
          if (ts.isStringLiteral(firstArg)) {
            const algo = firstArg.text.toLowerCase();

            for (const [pattern, label] of WEAK_ALGOS) {
              if (algo.includes(pattern)) {
                const span = firstArg.getStart(sourceFile);
                const loc = getLocation(sourceFile, span);

                findings.push({
                  ruleId: 'no-weak-crypto',
                  message: `Weak cryptographic algorithm "${label}" detected in ${callee.name.text}()`,
                  severity: Severity.High,
                  file: context.fileName,
                  line: loc.line,
                  column: loc.column,
                  endLine: loc.line,
                  endColumn: loc.column + firstArg.text.length + 2,
                  suggestion: 'Use SHA-256/SHA-512 for hashing, AES-256-GCM for encryption',
                });
                break;
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
