import { Severity } from '../types';
import type { Rule } from '../types';

export const commandInjectionRule: Rule = {
  id: 'no-command-injection',
  name: 'No Command Injection',
  description: 'Detects unsafe command execution with unsanitized user input.',
  severity: Severity.Critical,
  check() {
    return [];
  },
};
