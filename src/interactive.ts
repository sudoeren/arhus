import { select, checkbox, confirm, Separator } from '@inquirer/prompts';
import chalk from 'chalk';
import ora from 'ora';
import { resolve } from 'node:path';
import { loadConfig } from './config';
import { registerAllRules } from './rules/index';
import { getRules } from './rule';
import { scanFiles } from './scanner';
import { applyFixes } from './fixer';
import { terminalReport, jsonReport, sarifReport } from './reporter';
import type { Finding, ArhusConfig } from './types';

export async function interactiveMode(targetPath?: string) {
  console.log('');
  console.log('  ' + chalk.bold.cyan('arhus') + chalk.dim(' — scan. fix. repeat.'));
  console.log('');

  const action = await select({
    message: 'What would you like to do?',
    choices: [
      { name: 'Scan for vulnerabilities', value: 'scan', description: 'Static analysis' },
      { name: 'Auto-fix detected issues', value: 'fix', description: 'Apply suggested fixes' },
      { name: 'Create .arhusrc', value: 'init', description: 'Configuration file' },
      new Separator(),
      { name: 'Exit', value: 'exit' },
    ],
  });

  if (action === 'scan') {
    await interactiveScan(targetPath);
  } else if (action === 'fix') {
    await interactiveFix(targetPath);
  } else if (action === 'init') {
    await interactiveInit();
  }
}

async function interactiveScan(presetPath?: string) {
  const cwd = resolve(presetPath ?? '.');
  const config = loadConfig(cwd);
  registerAllRules();
  const rules = getRules();

  console.log(chalk.dim(`\n  Scanning: ${cwd}\n`));

  const proceed = await confirm({
    message: 'Proceed with scan?',
    default: true,
  });

  if (!proceed) {
    console.log(chalk.dim('\n  Cancelled.\n'));
    return;
  }
  const spinner = ora({
    text: chalk.dim(`Scanning with ${rules.length} rules...`),
    color: 'cyan',
  }).start();

  const results = await scanFiles(cwd, config);  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);

  if (totalFindings === 0) {
    spinner.succeed(chalk.green('No issues found!'));
    console.log('');
    return;
  }

  spinner.info(`Found ${totalFindings} issue${totalFindings !== 1 ? 's' : ''}`);
  console.log('');

  console.log(terminalReport(results));

  const format = await select({
    message: 'Export results?',
    choices: [
      { name: 'Done', value: 'none' },
      { name: 'Export as JSON', value: 'json' },
      { name: 'Export as SARIF', value: 'sarif' },
    ],
  });

  if (format === 'json') {
    console.log(jsonReport(results));
  } else if (format === 'sarif') {
    console.log(sarifReport(results));
  }

  console.log('');
}

async function interactiveFix(presetPath?: string) {
  const cwd = resolve(presetPath ?? '.');
  const config = loadConfig(cwd);
  registerAllRules();
  const rules = getRules();

  console.log(chalk.dim(`\n  Scanning: ${cwd}\n`));

  const proceed = await confirm({
    message: 'Proceed with fix scan?',
    default: true,
  });

  if (!proceed) {
    console.log(chalk.dim('\n  Cancelled.\n'));
    return;
  }
  const spinner = ora({
    text: chalk.dim(`Scanning with ${rules.length} rules...`),
    color: 'cyan',
  }).start();

  const results = await scanFiles(cwd, config);  const allFindings: Finding[] = [];

  for (const r of results) {
    for (const f of r.findings) {
      allFindings.push({ ...f, file: r.file });
    }
  }

  const fixable = allFindings.filter(f => f.suggestion);
  spinner.info(`Found ${allFindings.length} issue${allFindings.length !== 1 ? 's' : ''}, ${fixable.length} fixable`);

  if (allFindings.length === 0) {
    console.log(chalk.green('\n  No issues to fix!\n'));
    return;
  }

  console.log('');
  console.log(terminalReport(results));

  if (fixable.length === 0) {
    console.log(chalk.yellow('  No auto-fix suggestions available.\n'));
    return;
  }

  const choices = fixable.map(f => ({
    name: `[${f.ruleId}] ${f.file}:${f.line}  ${chalk.dim(f.suggestion ?? '')}`,
    value: f,
    checked: true,
  }));

  const selected = await checkbox({
    message: 'Select findings to auto-fix:',
    choices,
  });

  if (selected.length === 0) {
    console.log(chalk.dim('\n  Nothing selected.\n'));
    return;
  }

  const apply = await confirm({
    message: `Apply ${selected.length} fix${selected.length !== 1 ? 'es' : ''}?`,
    default: false,
  });

  if (!apply) {
    console.log(chalk.dim('\n  Cancelled.\n'));
    return;
  }

  const absoluteFindings = (selected as Finding[]).map(f => ({
    ...f,
    file: resolve(cwd, f.file),
  }));

  const fixResults = applyFixes(absoluteFindings, false);

  console.log('');
  for (const fr of fixResults) {
    console.log(`  ${chalk.green('✓')} ${fr.file}: ${fr.fixed} fixed, ${fr.skipped} skipped`);
  }

  console.log(chalk.green('\n  Fixes applied! Review changes before committing.\n'));
}

async function interactiveInit() {
  const apply = await confirm({
    message: 'Create .arhusrc in this directory?',
    default: true,
  });

  if (!apply) {
    console.log(chalk.dim('\n  Cancelled.\n'));
    return;
  }

  const fs = await import('node:fs');
  const configPath = resolve(process.cwd(), '.arhusrc');

  if (fs.existsSync(configPath)) {
    console.log(chalk.yellow('\n  .arhusrc already exists.\n'));
    return;
  }

  const defaultConfig: ArhusConfig = {
    include: ['**/*.{ts,tsx,js,jsx}'],
    exclude: ['node_modules/**', 'dist/**', '.git/**', 'coverage/**', '**/*.test.*', '**/test/**', 'tests/**'],
    rules: {},
  };

  fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf-8');
  console.log(chalk.green(`\n  Created ${configPath}\n`));
}
