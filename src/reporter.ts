import chalk from 'chalk';
import type { ScanResult, Finding } from './types';
import { Severity } from './types';

const severityIcon: Record<Severity, string> = {
  [Severity.Critical]: chalk.bgRed.white(' CRITICAL '),
  [Severity.High]: chalk.red(' HIGH     '),
  [Severity.Medium]: chalk.yellow(' MEDIUM   '),
  [Severity.Low]: chalk.blue(' LOW      '),
  [Severity.Info]: chalk.gray(' INFO     '),
};

export function terminalReport(results: ScanResult[]): string {
  if (results.length === 0) {
    return chalk.green('\n  No security issues found.\n');
  }

  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const lines: string[] = [];

  lines.push('');
  for (const result of results) {
    lines.push(chalk.underline(result.file));
    for (const f of result.findings) {
      const icon = severityIcon[f.severity] ?? '';
      lines.push(`  ${icon} ${chalk.gray(`${f.line}:${f.column}`)}  ${f.message}  ${chalk.dim(`[${f.ruleId}]`)}`);
    }
    lines.push('');
  }

  const summary = `${totalFindings} finding${totalFindings !== 1 ? 's' : ''}`;
  lines.push(chalk.bold(`  ${summary}`));
  lines.push('');

  return lines.join('\n');
}

export function jsonReport(results: ScanResult[]): string {
  return JSON.stringify(results, null, 2);
}

export function sarifReport(results: ScanResult[]): string {
  const rules = extractRules(results);
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'arhus',
          informationUri: 'https://github.com/sudoeren/arhus',
          rules,
        },
      },
      results: results.flatMap(r => r.findings.map(f => ({
        ruleId: f.ruleId,
        message: { text: f.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: r.file },
            region: {
              startLine: f.line,
              startColumn: f.column,
              endLine: f.endLine ?? f.line,
              endColumn: f.endColumn ?? f.column,
            },
          },
        }],
      }))),
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

function extractRules(results: ScanResult[]) {
  const seen = new Set<string>();
  const rules: { id: string; name: string; shortDescription: { text: string } }[] = [];

  for (const r of results) {
    for (const f of r.findings) {
      if (!seen.has(f.ruleId)) {
        seen.add(f.ruleId);
        rules.push({
          id: f.ruleId,
          name: f.ruleId,
          shortDescription: { text: f.ruleId },
        });
      }
    }
  }

  return rules;
}
