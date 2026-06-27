import type { Rule, ArhusConfig, Severity, RuleOptions } from './types';

const registry = new Map<string, Rule>();

export function registerRule(rule: Rule): void {
  if (registry.has(rule.id)) {
    throw new Error(`Rule "${rule.id}" is already registered`);
  }
  registry.set(rule.id, rule);
}

export function getRule(id: string): Rule | undefined {
  return registry.get(id);
}

export function getRules(): Rule[] {
  return Array.from(registry.values());
}

export function getActiveRules(config: ArhusConfig): Rule[] {
  const all = getRules();
  const configured = config.rules ?? {};

  return all
    .filter(rule => {
      const setting = configured[rule.id];
      if (setting === false) return false;
      return true;
    })
    .map(rule => {
      const setting = configured[rule.id];
      if (!setting || setting === true) return rule;

      let severity: Severity | undefined;
      let options: RuleOptions | undefined;

      if (typeof setting === 'string') {
        severity = setting as Severity;
      } else if (typeof setting === 'object') {
        severity = setting.severity;
        options = setting;
      }

      if (severity) {
        const originalCheck = rule.check;
        return {
          ...rule,
          severity,
          check(context) {
            const findings = originalCheck(context);
            return findings.map(f => ({ ...f, severity }));
          },
        };
      }

      return rule;
    });
}

export function clearRules(): void {
  registry.clear();
}
