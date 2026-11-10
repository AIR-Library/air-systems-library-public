# Feature Flags (Openfeature-Style Evaluation)

Reference contract for `saas_templates/<lang>/feature_flags_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# FLAG-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `FLAG-01` | unknown flag returns the default, does NOT throw, error_code FLAG_NOT_FOUND, reason ERROR |
| `FLAG-02` | calling the string method on a boolean flag returns the default with TYPE_MISMATCH |
| `FLAG-03` | a disabled flag returns the default with reason DISABLED |
| `FLAG-04` | a matching rule returns its value and variant with TARGETING_MATCH; a non-matching one does not |
| `FLAG-05` | a 30% rollout (boolean flag, default false, one rule {conditions: [], value: true, |
| `FLAG-06` | a user outside a rollout falls through to the NEXT rule (or the default), never a variant |
| `FLAG-07` | corrupt rules JSON returns the default with PARSE_ERROR, no exception |
| `FLAG-08` | set_flag writes an audit row with old and new values |

## Contract

```text
Source: OpenFeature specification, Flag Evaluation API (Apache-2.0).

PURPOSE:
  Turn features on/off per user, org or tier, and roll them out to a percentage, without redeploying.

SCHEMA:
  feature_flags (key PRIMARY, type 'boolean'|'string'|'number'|'object', default_value JSON,
                 enabled BOOL, rules JSON, updated_at, updated_by)
  flag_audit    (id, flag_key, action, old_value JSON, new_value JSON, actor_id, at)

ENDPOINTS / FUNCTIONS:
  get_boolean_value(flag_key, default_value, context) -> bool
  get_string_value / get_number_value / get_object_value -> same pattern
  get_boolean_details(flag_key, default_value, context) -> {flag_key, value, variant, reason,
      error_code, error_message}   (and the same *_details for the other types)
  set_flag(actor, key, type, default_value, enabled, rules)   -- audited
  context = {targeting_key, user_id, org_id, tier, email, ...any attributes}

IMPLEMENTATION -- RULES (quoted):
  - "Methods, functions, or operations on the client MUST NOT throw exceptions, or otherwise abnormally
    terminate. Flag evaluation calls must always return the default value in the event of abnormal
    execution." Every evaluation catches everything and returns the caller's default.
  - reason is one of STATIC, DEFAULT, TARGETING_MATCH, SPLIT, DISABLED, ERROR.
  - error_code on failure: FLAG_NOT_FOUND (unknown key), TYPE_MISMATCH (stored type differs from the
    method called), PARSE_ERROR (bad rules), GENERAL (anything else).
  - "In cases of abnormal execution ... the reason field in the evaluation details SHOULD indicate an
    error": every error_code above comes with reason ERROR and the caller's default value.
  - Disabled flag -> default value, reason DISABLED.
  - The rules JSON has EXACTLY this shape in every language (the last build let each language invent
    its own, so no two libraries agreed and several tests could not express a rollout at all):
        [ { "conditions": [ {"attribute": "email", "operator": "ends_with", "value": "@acme.com"} ],
            "variant": "on",
            "value": true,
            "rollout": null } ,
          { "conditions": [], "variant": "beta", "value": true, "rollout": {"percentage": 30} } ]
    A rule MATCHES when ALL its conditions match (an empty list matches everyone). The attribute is
    looked up in context (targeting_key, user_id, org_id, tier, email, or any other key).
    Operators: equals, not_equals, in_list (value is a list), ends_with (for email domains).
  - Rules are evaluated in order; the first rule that APPLIES wins:
      no rollout            -> it applies: serve its value, variant, reason TARGETING_MATCH.
      rollout {percentage}  -> it applies ONLY if bucket < percentage: serve its value, variant, reason
                               SPLIT. Otherwise it does NOT apply and evaluation moves to the next rule.
    No rule applies -> the flag's stored default_value, reason DEFAULT.
  - Percentage rollout is DETERMINISTIC: bucket = stable_hash(flag_key + ":" + targeting_key) % 100.
    The same user always lands in the same bucket. Never use random(). stable_hash is a FIXED algorithm
    -- the first 8 bytes of SHA-256 as an unsigned big-endian integer, and ONLY that (amended 2026-09-26:
    allowing FNV-1a as well meant two correct builds put the same user in different buckets) -- never a
    language's built-in or default hasher (Rust's DefaultHasher is documented as unstable across
    releases; Python's hash() of a str changes every process).
  - A served value whose type is not the flag's type -> caller's default, TYPE_MISMATCH.

TESTS:
  - **FLAG-01** unknown flag returns the default, does NOT throw, error_code FLAG_NOT_FOUND, reason ERROR
  - **FLAG-02** calling the string method on a boolean flag returns the default with TYPE_MISMATCH
  - **FLAG-03** a disabled flag returns the default with reason DISABLED
  - **FLAG-04** a matching rule returns its value and variant with TARGETING_MATCH; a non-matching one does not
  - **FLAG-05** a 30% rollout (boolean flag, default false, one rule {conditions: [], value: true,
    rollout: {percentage: 30}}): the same targeting_key gives the same answer every call, and over
    10,000 keys between 25% and 35% are true
  - **FLAG-06** a user outside a rollout falls through to the NEXT rule (or the default), never a variant
  - **FLAG-07** corrupt rules JSON returns the default with PARSE_ERROR, no exception
  - **FLAG-08** set_flag writes an audit row with old and new values
```
