import { registerRule } from '../rule';

import { hardcodedSecretsRule } from './hardcoded-secrets';
import { unsafeRegexRule } from './unsafe-regex';
import { xssDomRule } from './xss-dom';
import { pathTraversalRule } from './path-traversal';
import { sqlInjectionRule } from './sql-injection';
import { commandInjectionRule } from './command-injection';
import { debuggerRule } from './debugger';

export function registerAllRules(): void {
  registerRule(hardcodedSecretsRule);
  registerRule(unsafeRegexRule);
  registerRule(xssDomRule);
  registerRule(pathTraversalRule);
  registerRule(sqlInjectionRule);
  registerRule(commandInjectionRule);
  registerRule(debuggerRule);
}
