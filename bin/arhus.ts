#!/usr/bin/env node
import { Command } from 'commander';
import { relative, resolve } from 'node:path';
import { loadConfig } from '../src/config';
import { registerAllRules } from '../src/rules/index';
import { scanFiles } from '../src/scanner';
import { applyFixes } from '../src/fixer';
import { terminalReport, jsonReport, sarifReport } from '../src/reporter';
import { interactiveMode } from '../src/interactive';
import type { ArhusConfig } from '../src/types';

const program = new Command();

program
  .name('arhus')
  .description('scan. fix. repeat. — local-first security analysis')
  .version('0.1.0');

program
  .command('scan [path]')
  .description('Scan a directory for security vulnerabilities')
  .option('-f, --format <format>', 'output format: terminal, json, sarif', 'terminal')
  .action(async (targetPath = '.', options: { format: string }) => {
    const cwd = resolve(targetPath);
    const config = loadConfig(cwd);
    registerAllRules();

    console.log(`\n  Scanning ${relative(process.cwd(), cwd) || '.'}...\n`);

    const results = await scanFiles(cwd, config);
    switch (options.format) {
      case 'json':
        console.log(jsonReport(results));
        break;
      case 'sarif':
        console.log(sarifReport(results));
        break;
      default:
        console.log(terminalReport(results));
    }

    const total = results.reduce((s, r) => s + r.findings.length, 0);
    if (total > 0) {
      process.exit(1);
    }
  });

program
  .command('fix [path]')
  .description('Auto-fix detected security issues')
  .option('--dry-run', 'Preview fixes without applying them')
  .action(async (targetPath = '.', options: { dryRun?: boolean }) => {
    const cwd = resolve(targetPath);
    const config = loadConfig(cwd);
    registerAllRules();

    const results = await scanFiles(cwd, config);    const allFindings = results.flatMap(r => r.findings.map(f => ({ ...f, file: resolve(cwd, r.file) })));

    const fixResults = applyFixes(
      allFindings.filter(f => f.suggestion),
      options.dryRun ?? false,
    );

    for (const fr of fixResults) {
      const relPath = relative(process.cwd(), fr.file);
      if (options.dryRun) {
        console.log(`  ${relPath}: ${fr.fixed} fix(es) available (dry run)`);
      } else {
        console.log(`  ${relPath}: ${fr.fixed} fixed, ${fr.skipped} skipped`);
      }
    }
  });

program
  .command('init')
  .description('Create a default .arhusrc configuration file')
  .action(async () => {
    const fs = await import('node:fs');
    const configPath = resolve(process.cwd(), '.arhusrc');

    if (fs.existsSync(configPath)) {
      console.log(`  .arhusrc already exists at ${configPath}`);
      return;
    }

    const defaultConfig: ArhusConfig = {
      include: ['**/*.{ts,tsx,js,jsx}'],
      exclude: ['node_modules/**', 'dist/**', '.git/**', 'coverage/**', '**/*.test.*', '**/test/**', 'tests/**'],
      rules: {},
    };

    fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf-8');
    console.log(`  Created .arhusrc at ${configPath}`);
  });

if (process.argv.length <= 2) {
  interactiveMode();
} else {
  program.parse();
}
