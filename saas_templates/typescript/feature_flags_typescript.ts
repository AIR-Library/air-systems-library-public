import * as crypto from 'crypto';

interface FlagRecord {
  key: string;
  type: 'boolean' | 'string' | 'number' | 'object';
  default_value: unknown;
  enabled: boolean;
  rules: unknown[] | string;
  updated_at: string;
  updated_by: string;
}

interface AuditRecord {
  id: number;
  flag_key: string;
  action: string;
  old_value: unknown;
  new_value: unknown;
  actor_id: string;
  at: string;
}

interface EvaluationDetails {
  flag_key: string;
  value: unknown;
  variant: string | null;
  reason: string;
  error_code: string | null;
  error_message: string | null;
}

type Context = {
  targeting_key?: string;
  user_id?: string;
  org_id?: string;
  tier?: string;
  email?: string;
  [key: string]: unknown;
};

interface FlagStore {
  getFlag(key: string): FlagRecord | null;
  setFlag(key: string, flag: FlagRecord): void;
  addAudit(audit: AuditRecord): void;
  getAudits(flagKey: string): AuditRecord[];
}

class InMemoryFlagStore implements FlagStore {
  private flags = new Map<string, FlagRecord>();
  private audits = new Map<string, AuditRecord[]>();
  private auditIdCounter = 0;

  getFlag(key: string): FlagRecord | null {
    return this.flags.get(key) ?? null;
  }

  setFlag(key: string, flag: FlagRecord): void {
    this.flags.set(key, flag);
  }

  addAudit(audit: AuditRecord): void {
    const list = this.audits.get(audit.flag_key) ?? [];
    list.push(audit);
    this.audits.set(audit.flag_key, list);
  }

  getAudits(flagKey: string): AuditRecord[] {
    return this.audits.get(flagKey) ?? [];
  }
}

const SQL_SCHEMA = `
CREATE TABLE IF NOT EXISTS feature_flags (
  key TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('boolean', 'string', 'number', 'object')),
  default_value TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  rules TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flag_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  flag_key TEXT NOT NULL,
  action TEXT NOT NULL,
  old_value TEXT,
  new_value TEXT,
  actor_id TEXT NOT NULL,
  at TEXT NOT NULL,
  FOREIGN KEY (flag_key) REFERENCES feature_flags(key)
);
`;

/**
 * stable_hash from the spec: the first 8 bytes of SHA-256(input) read as an unsigned big-endian integer.
 *
 * In: the string `flag_key + ":" + targeting_key`. Out: a bigint in [0, 2^64).
 * Why: spec FLAG-05 fixes the algorithm so every language puts a user in the same bucket. The previous
 * version accumulated the 8 bytes in a JS number (a double, exact only to 2^53), so `% 100` gave a
 * different bucket from the other seven languages for most keys (e.g. "rollout_flag:user0": 16 here,
 * 84 everywhere else). BigInt keeps all 64 bits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing (pure function).
 */
function stableHash(input: string): bigint {
  return crypto.createHash('sha256').update(input).digest().readBigUInt64BE(0);
}

function evaluateConditions(conditions: unknown[], context: Context): boolean {
  if (!conditions || conditions.length === 0) {
    return true;
  }
  for (const cond of conditions) {
    if (typeof cond !== 'object' || cond === null) return false;
    const c = cond as Record<string, unknown>;
    const attribute = c.attribute as string | undefined;
    const operator = c.operator as string | undefined;
    const value = c.value;
    if (!attribute || !operator) return false;
    const contextValue = context[attribute];
    switch (operator) {
      case 'equals':
        if (contextValue !== value) return false;
        break;
      case 'not_equals':
        if (contextValue === value) return false;
        break;
      case 'in_list':
        if (!Array.isArray(value) || !value.includes(contextValue)) return false;
        break;
      case 'ends_with':
        if (typeof contextValue !== 'string' || !contextValue.endsWith(value as string)) return false;
        break;
      default:
        return false;
    }
  }
  return true;
}

export class FeatureFlags {
  private store: FlagStore;

  constructor(store?: FlagStore) {
    this.store = store ?? new InMemoryFlagStore();
  }

  set_flag(
    actor: string,
    key: string,
    type: 'boolean' | 'string' | 'number' | 'object',
    default_value: unknown,
    enabled: boolean,
    rules: unknown[] | string
  ): void {
    const now = new Date().toISOString();
    const existingFlag = this.store.getFlag(key);

    const newFlag: FlagRecord = {
      key,
      type,
      default_value,
      enabled,
      rules,
      updated_at: now,
      updated_by: actor
    };

    const audit: AuditRecord = {
      id: 0,
      flag_key: key,
      action: existingFlag ? 'UPDATE' : 'CREATE',
      old_value: existingFlag?.default_value ?? null,
      new_value: default_value,
      actor_id: actor,
      at: now
    };

    this.store.setFlag(key, newFlag);
    this.store.addAudit(audit);
  }

  get_boolean_value(flag_key: string, default_value: boolean, context: Context = {}): boolean {
    return this.get_boolean_details(flag_key, default_value, context).value as boolean;
  }

  get_boolean_details(flag_key: string, default_value: boolean, context: Context = {}): EvaluationDetails {
    return this.evaluateFlag(flag_key, default_value, context, 'boolean');
  }

  get_string_value(flag_key: string, default_value: string, context: Context = {}): string {
    return this.get_string_details(flag_key, default_value, context).value as string;
  }

  get_string_details(flag_key: string, default_value: string, context: Context = {}): EvaluationDetails {
    return this.evaluateFlag(flag_key, default_value, context, 'string');
  }

  get_number_value(flag_key: string, default_value: number, context: Context = {}): number {
    return this.get_number_details(flag_key, default_value, context).value as number;
  }

  get_number_details(flag_key: string, default_value: number, context: Context = {}): EvaluationDetails {
    return this.evaluateFlag(flag_key, default_value, context, 'number');
  }

  get_object_value(flag_key: string, default_value: object, context: Context = {}): object {
    return this.get_object_details(flag_key, default_value, context).value as object;
  }

  get_object_details(flag_key: string, default_value: object, context: Context = {}): EvaluationDetails {
    return this.evaluateFlag(flag_key, default_value, context, 'object');
  }

  private evaluateFlag(
    flag_key: string,
    default_value: unknown,
    context: Context,
    expected_type: 'boolean' | 'string' | 'number' | 'object'
  ): EvaluationDetails {
    try {
      const flag = this.store.getFlag(flag_key);

      if (!flag) {
        return {
          flag_key,
          value: default_value,
          variant: null,
          reason: 'ERROR',
          error_code: 'FLAG_NOT_FOUND',
          error_message: `Flag with key '${flag_key}' not found`
        };
      }

      if (flag.type !== expected_type) {
        return {
          flag_key,
          value: default_value,
          variant: null,
          reason: 'ERROR',
          error_code: 'TYPE_MISMATCH',
          error_message: `Flag type '${flag.type}' does not match expected type '${expected_type}'`
        };
      }

      if (!flag.enabled) {
        return {
          flag_key,
          value: default_value,
          variant: null,
          reason: 'DISABLED',
          error_code: null,
          error_message: null
        };
      }

      let rules: unknown[];
      try {
        if (Array.isArray(flag.rules)) {
          rules = flag.rules;
        } else {
          rules = JSON.parse(flag.rules as string);
        }
      } catch {
        return {
          flag_key,
          value: default_value,
          variant: null,
          reason: 'ERROR',
          error_code: 'PARSE_ERROR',
          error_message: 'Failed to parse flag rules'
        };
      }

      for (const rule of rules) {
        if (typeof rule !== 'object' || rule === null) continue;
        const r = rule as Record<string, unknown>;
        const conditions = (r.conditions as unknown[]) ?? [];
        const matches = evaluateConditions(conditions, context);

        if (matches) {
          const rollout = r.rollout as Record<string, unknown> | null;
          if (rollout && typeof rollout.percentage === 'number') {
            const targetingKey = (context.targeting_key as string) ?? '';
            const bucket = Number(stableHash(`${flag_key}:${targetingKey}`) % 100n);
            if (bucket < rollout.percentage) {
              return {
                flag_key,
                value: r.value,
                variant: r.variant as string,
                reason: 'SPLIT',
                error_code: null,
                error_message: null
              };
            }
          } else {
            return {
              flag_key,
              value: r.value,
              variant: r.variant as string,
              reason: 'TARGETING_MATCH',
              error_code: null,
              error_message: null
            };
          }
        }
      }

      return {
        flag_key,
        value: flag.default_value,
        variant: null,
        reason: 'DEFAULT',
        error_code: null,
        error_message: null
      };
    } catch (error) {
      return {
        flag_key,
        value: default_value,
        variant: null,
        reason: 'ERROR',
        error_code: 'GENERAL',
        error_message: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }
}

export { InMemoryFlagStore, SQL_SCHEMA };