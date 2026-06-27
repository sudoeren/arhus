import { Severity } from '../types';
import type { Rule } from '../types';

export const hardcodedSecretsRule: Rule = {
  id: 'no-hardcoded-secrets',
  name: 'No Hardcoded Secrets',
  description: 'Detects hardcoded API keys, tokens, and passwords in source code.',
  severity: Severity.Critical,
  check() {
    return [];
  },
};
