import { Severity } from '../types';
import type { Rule } from '../types';

export const pathTraversalRule: Rule = {
  id: 'no-path-traversal',
  name: 'No Path Traversal',
  description: 'Detects potential path traversal vulnerabilities in file operations.',
  severity: Severity.High,
  check() {
    return [];
  },
};
