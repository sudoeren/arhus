import { intro, outro, select, text, confirm, multiselect, spinner, note, cancel, isCancel } from '@clack/prompts';
import chalk from 'chalk';
import { resolve } from 'node:path';
import { loadConfig } from './config';
import { registerAllRules } from './rules/index';
import { getRules } from './rule';
import { scanFiles } from './scanner';
import { applyFixes } from './fixer';
import { terminalReport, jsonReport, sarifReport } from './reporter';
import type { Finding, ArgusConfig } from './types';

export async function interactiveMode(targetPath?: string) {
  intro(chalk.bold.cyan('  argus — scan. fix. repeat.'));

  const action = await select({
    message: 'What would you like to do?',
    options: [
      { value: 'scan', label: ' Scan for vulnerabilities', hint: 'static analysis' },
      { value: 'fix', label: ' Auto-fix detected issues', hint: 'apply suggested fixes' },
      { value: 'init', label: ' Create .argusrc.json', hint: 'configuration file' },
      { value: 'exit', label: ' Exit', hint: '' },
    ],
  });

  if (isCancel(action) || action === 'exit') {
    cancel('Goodbye!');
    process.exit(0);
  }

  if (action === 'scan') {
    await interactiveScan(targetPath);
  } else if (action === 'fix') {
    await interactiveFix(targetPath);
  } else if (action === 'init') {
    await interactiveInit();
  }
}

async function interactiveScan(presetPath?: string) {
  const pathInput = await text({
    message: 'Directory to scan:',
    placeholder: presetPath ?? '.',
    defaultValue: presetPath ?? '.',
  });

  if (isCancel(pathInput)) {
    cancel('Cancelled');
    process.exit(0);
  }

  const cwd = resolve(pathInput as string);
  const config = loadConfig(cwd);
  registerAllRules();
  const rules = getRules();

  const s = spinner();
  s.start(`Scanning with ${rules.length} rules...`);

  const results = await scanFiles(cwd, config.include, config.exclude);

  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  s.stop(totalFindings === 0 ? 'No issues found!' : `Found ${totalFindings} issue${totalFindings !== 1 ? 's' : ''}`);

  if (totalFindings === 0) {
    note(chalk.green('  Your code looks secure!'), 'Result');
    outro('Done!');
    return;
  }

  console.log(terminalReport(results));

  const format = await select({
    message: 'Export results?',
    options: [
      { value: 'none', label: ' Done', hint: 'finish' },
      { value: 'json', label: ' Export as JSON', hint: '' },
      { value: 'sarif', label: ' Export as SARIF', hint: 'GitHub Code Scanning' },
    ],
  });

  if (isCancel(format) || format === 'none') {
    outro('Done!');
    return;
  }

  if (format === 'json') {
    console.log(jsonReport(results));
  } else if (format === 'sarif') {
    console.log(sarifReport(results));
  }

  outro('Done!');
}

async function interactiveFix(presetPath?: string) {
  const pathInput = await text({
    message: 'Directory to fix:',
    placeholder: presetPath ?? '.',
    defaultValue: presetPath ?? '.',
  });

  if (isCancel(pathInput)) {
    cancel('Cancelled');
    process.exit(0);
  }

  const cwd = resolve(pathInput as string);
  const config = loadConfig(cwd);
  registerAllRules();
  const rules = getRules();

  const s = spinner();
  s.start(`Scanning with ${rules.length} rules...`);

  const results = await scanFiles(cwd, config.include, config.exclude);
  const allFindings: Finding[] = [];

  for (const r of results) {
    for (const f of r.findings) {
      allFindings.push({ ...f, file: r.file });
    }
  }

  const fixableCount = allFindings.filter(f => f.suggestion).length;
  s.stop(`Found ${allFindings.length} issue${allFindings.length !== 1 ? 's' : ''}, ${fixableCount} fixable`);

  if (allFindings.length === 0) {
    note(chalk.green('  No issues to fix!'), 'Result');
    outro('Done!');
    return;
  }

  console.log(terminalReport(results));

  if (fixableCount === 0) {
    note('No auto-fix suggestions available for these findings.', 'Warning');
    outro('Done!');
    return;
  }

  const choices = allFindings
    .filter(f => f.suggestion)
    .map(f => ({
      value: f,
      label: `[${f.ruleId}] ${f.file}:${f.line} — ${f.message}`,
      hint: f.suggestion ?? '',
    }));

  const selected = await multiselect({
    message: 'Select findings to auto-fix:',
    options: choices,
    required: false,
  });

  if (isCancel(selected)) {
    cancel('Cancelled');
    process.exit(0);
  }

  if (!selected || selected.length === 0) {
    note('No findings selected.', 'Info');
    outro('Done!');
    return;
  }

  const apply = await confirm({
    message: `Apply ${selected.length} fix${selected.length !== 1 ? 'es' : ''}?`,
  });

  if (isCancel(apply) || !apply) {
    cancel('Cancelled');
    process.exit(0);
  }

  const absoluteFindings = (selected as Finding[]).map(f => ({
    ...f,
    file: resolve(cwd, f.file),
  }));

  const fixResults = applyFixes(absoluteFindings, false);

  for (const fr of fixResults) {
    console.log(`  ${chalk.green('✓')} ${fr.file}: ${fr.fixed} fixed, ${fr.skipped} skipped`);
  }

  note('Fixes applied! Review the changes before committing.', 'Success');
  outro('Done!');
}

async function interactiveInit() {
  const confirmCreate = await confirm({
    message: 'Create .argusrc.json in the current directory?',
  });

  if (isCancel(confirmCreate) || !confirmCreate) {
    cancel('Cancelled');
    process.exit(0);
  }

  const fs = await import('node:fs');
  const configPath = resolve(process.cwd(), '.argusrc.json');

  if (fs.existsSync(configPath)) {
    note('.argusrc.json already exists.', 'Warning');
    outro('Done!');
    return;
  }

  const defaultConfig: ArgusConfig = {
    include: ['**/*.{ts,tsx,js,jsx}'],
    exclude: ['node_modules/**', 'dist/**', '.git/**', 'coverage/**'],
    rules: {},
  };

  fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf-8');
  note(`Created ${configPath}`, 'Success');
  outro('Done!');
}
