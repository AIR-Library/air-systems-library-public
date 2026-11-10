'use strict';
const crypto = require('node:crypto');

/**
 * Secret & PII screening (docs/specs/secret_pii_screening.md): find secrets (API keys, tokens, private keys,
 * passwords in URLs and in assignments) and personal data (emails, phones, cards, IP addresses, US SSNs) in a text
 * BEFORE it is stored, logged or shared, and either refuse the text ("reject", the default) or replace each match
 * with a "[REDACTED:<label>]" marker ("strip").
 *
 * Every detector follows the spec's MATCHING procedure: core regexes compiled with no u/i/m flag (the "g" flag is
 * only used to start a search at `pos` through lastIndex), the guards and checks written as plain loops, and
 * detectors 2 (cut-off PEM), 10 (JWT) and 13 (key = value) written as procedures so the scan stays linear.
 * Offsets are found in UTF-16 units (JavaScript's own unit) and converted to Unicode code points before they leave.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (SCREEN-01..SCREEN-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing outside memory (no database, files, network or money). Never logs the text, a matched value or
 * the hash key.
 */

const DEFAULT_MAX_BYTES = 1048576;
const VALID_CATEGORIES = new Set(['secret', 'pii']);
const PLACEHOLDERS = new Set([
  'changeme', 'change_me', 'your_key_here', 'your-key-here', 'xxx', 'xxxx', 'xxxxx', 'redacted', 'todo', 'example',
  'placeholder', 'secret', 'password', 'insert_key_here', 'none', 'null', 'n/a', 'na', '<your-password>',
  '<your-key>', 'fillmein'
]);
const REDACTED_PREFIX = '[REDACTED:';

/**
 * ScreeningError: thrown only by newScreener when the hash key is too short (fail closed, no screener exists).
 * In: code (e.g. "invalid_hash_key"). Out: an Error with `.code`. Why: SCREEN-12.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
class ScreeningError extends Error {
  /**
   * In: the error code. Out: the error, with `.code` set and the code as its only message (no secret).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1). Touches nothing.
   */
  constructor(code) {
    super(code);
    this.name = 'ScreeningError';
    this.code = code;
  }
}

/* ------------------------------------------------------------------ character helpers */

/**
 * The UTF-16 code unit at i, or -1 ("none") outside the text. In: text, index. Out: number.
 * Why: the spec's "before"/"after" are none at either end. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function codeAt(text, i) {
  return i >= 0 && i < text.length ? text.charCodeAt(i) : -1;
}

/** True for a digit 0-9 (code unit). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function isDigit(c) {
  return c >= 48 && c <= 57;
}

/** True for A-Z or a-z (code unit). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function isAlpha(c) {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

/** True for W = [A-Za-z0-9_]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function isW(c) {
  return isAlpha(c) || isDigit(c) || c === 95;
}

/** "not W": none (-1) or a character outside W. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function notW(c) {
  return c === -1 || !isW(c);
}

/** True for a hex digit 0-9 A-F a-f. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function isHex(c) {
  return isDigit(c) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
}

/**
 * ASCII lower case: maps A-Z to a-z and nothing else, so positions never move (spec CONVENTIONS). In: text.
 * Out: text. Why: SCREEN-05 ("only A-Z is lower-cased"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function asciiLower(text) {
  return text.replace(/[A-Z]+/g, s => s.toLowerCase());
}

/**
 * Number of Unicode code points in a well-formed string. In: text. Out: integer.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function codePointLength(text) {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (!(c >= 0xdc00 && c <= 0xdfff && i > 0 && text.charCodeAt(i - 1) >= 0xd800 && text.charCodeAt(i - 1) <= 0xdbff)) n++;
  }
  return n;
}

/**
 * A map from UTF-16 index to code point index (length text.length + 1), or null when the text holds no surrogate
 * (then the two are the same). In: text. Out: Int32Array | null. Why: spec CONVENTIONS (start/end count code points).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function utf16ToCpMap(text) {
  if (!/[\uD800-\uDFFF]/.test(text)) return null;
  const map = new Int32Array(text.length + 1);
  let cp = 0;
  for (let i = 0; i < text.length; i++) {
    map[i] = cp;
    const c = text.charCodeAt(i);
    const isLowAfterHigh = c >= 0xdc00 && c <= 0xdfff && i > 0 &&
      text.charCodeAt(i - 1) >= 0xd800 && text.charCodeAt(i - 1) <= 0xdbff;
    if (isLowAfterHigh) map[i] = cp - 1; else cp++;
  }
  map[text.length] = cp;
  return map;
}

/**
 * mask(value): n code points; n < 16 -> "*" * n; otherwise the first 2, "*" * (n - 4), the last 2.
 * In: string. Out: string. Why: SCREEN-12 (a preview never shows a short value).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function mask(value) {
  const cps = Array.from(value);
  const n = cps.length;
  if (n < 16) return '*'.repeat(n);
  return cps[0] + cps[1] + '*'.repeat(n - 4) + cps[n - 2] + cps[n - 1];
}

/* ------------------------------------------------------------------ escapes */

const ESCAPE_TEST = /\\(?:u[0-9A-Fa-f]{4}|["\\/bfnrt])/;
const SIMPLE_ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\u0008', f: '\u000c', n: '\n', r: '\r', t: '\t' };

/**
 * True when the 4 characters at i are hex digits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function hex4At(text, i) {
  return i + 4 <= text.length && isHex(text.charCodeAt(i)) && isHex(text.charCodeAt(i + 1)) &&
    isHex(text.charCodeAt(i + 2)) && isHex(text.charCodeAt(i + 3));
}

/**
 * One left-to-right pass that replaces every ESCAPE (spec ESCAPES): \uXXXX by U+XXXX, a high + low surrogate escape
 * pair by the one character it encodes, any other surrogate by U+FFFD, \" \\ \/ \b \f \n \r \t by their character.
 * A backslash followed by anything else stays. In: text. Out: text. Why: SCREEN-13.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function resolveOnePass(text) {
  const parts = [];
  let last = 0;
  let i = text.indexOf('\\');
  while (i !== -1) {
    let consumed = 0;
    let replacement = '';
    const next = text[i + 1];
    if (next === 'u' && hex4At(text, i + 2)) {
      const code = parseInt(text.slice(i + 2, i + 6), 16);
      if (code >= 0xd800 && code <= 0xdbff && text[i + 6] === '\\' && text[i + 7] === 'u' && hex4At(text, i + 8)) {
        const low = parseInt(text.slice(i + 8, i + 12), 16);
        if (low >= 0xdc00 && low <= 0xdfff) {
          replacement = String.fromCharCode(code, low);
          consumed = 12;
        }
      }
      if (consumed === 0) {
        replacement = code >= 0xd800 && code <= 0xdfff ? '�' : String.fromCharCode(code);
        consumed = 6;
      }
    } else if (next !== undefined && Object.prototype.hasOwnProperty.call(SIMPLE_ESCAPES, next)) {
      replacement = SIMPLE_ESCAPES[next];
      consumed = 2;
    }
    if (consumed > 0) {
      parts.push(text.slice(last, i), replacement);
      last = i + consumed;
      i = text.indexOf('\\', last);
    } else {
      i = text.indexOf('\\', i + 1);
    }
  }
  parts.push(text.slice(last));
  return parts.join('');
}

/**
 * resolve_escapes(text): repeats the pass while the text holds an ESCAPE, at most 8 times.
 * In: text. Out: {text, unresolved} (unresolved = an ESCAPE is still there after the 8th pass). Why: SCREEN-13.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function resolveEscapes(text) {
  let out = text;
  for (let pass = 0; pass < 8 && ESCAPE_TEST.test(out); pass++) out = resolveOnePass(out);
  return { text: out, unresolved: ESCAPE_TEST.test(out) };
}

/* ------------------------------------------------------------------ detectors */

/**
 * find_all(detector, text) from the spec's MATCHING: the leftmost match at or after pos; when accept() takes it,
 * record its span and continue at the span's `next` (default the end of the match); otherwise at start + 1.
 * In: a global RegExp, the text it runs on, accept(m, start, end) -> {span: [s, e], next?} | null.
 * Out: [[s, e]] in UTF-16 units. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function findAll(re, text, accept) {
  const spans = [];
  let pos = 0;
  while (pos <= text.length) {
    re.lastIndex = pos;
    const m = re.exec(text);
    if (!m) break;
    const start = m.index;
    const end = start + m[0].length;
    const r = accept(m, start, end);
    if (r) {
      spans.push(r.span);
      pos = r.next !== undefined ? r.next : end;
    } else {
      pos = start + 1;
    }
  }
  return spans;
}

const RE = {
  pem: /-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\r?\n)?[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----/g,
  pemHeader: /-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----/g,
  openai: /sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]/g,
  stripe: /[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}/g,
  aws: /A[KS]IA[0-9A-Z]{16}/g,
  github: /gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}/g,
  slack: /xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]/g,
  google: /AIza[0-9A-Za-z_-]{35}/g,
  whsec: /whsec_[A-Za-z0-9+/=]{16,500}/g,
  bearer: /[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})/g,
  url: /[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@/g,
  generic: /(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key|credentials?|token)(?:\\?["'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?["'])?/g,
  email: /[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}/g,
  phone: /(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}/g,
  card: /[0-9](?:[ -]?[0-9]){12,18}/g,
  ssn: /[0-9]{3}-[0-9]{2}-[0-9]{4}/g,
  ipv4: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g,
  ipv6: /[0-9A-Fa-f:]{2,39}/g
};
const CARD_PREFIX = /^(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])/;

/** Has a digit 0-9. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function hasDigit(s) {
  for (let i = 0; i < s.length; i++) if (isDigit(s.charCodeAt(i))) return true;
  return false;
}

/**
 * Counts places where a letter a-z is directly followed by a letter A-Z. In: string. Out: integer.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function camelPlaces(s) {
  let n = 0;
  for (let i = 0; i + 1 < s.length; i++) {
    const a = s.charCodeAt(i);
    const b = s.charCodeAt(i + 1);
    if (a >= 97 && a <= 122 && b >= 65 && b <= 90) n++;
  }
  return n;
}

/**
 * looks_like_secret(v): a digit 0-9; or a character below U+0080 outside [A-Za-z0-9]; or 2+ a-z->A-Z places.
 * In: string. Out: bool. Why: detector 13 (SCREEN-05). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function looksLikeSecret(v) {
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (isDigit(c)) return true;
    if (c < 0x80 && !isAlpha(c)) return true;
  }
  return camelPlaces(v) >= 2;
}

/**
 * NAME: a letter A-Z a-z or "_" followed by letters, digits 0-9 and "_". In: string. Out: bool.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function isName(s) {
  if (s.length === 0) return false;
  const c0 = s.charCodeAt(0);
  if (!(isAlpha(c0) || c0 === 95)) return false;
  for (let i = 1; i < s.length; i++) if (!isW(s.charCodeAt(i))) return false;
  return true;
}

/** True when every piece of s split at "." is a NAME. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function allNames(s) {
  return s.split('.').every(isName);
}

/**
 * REFERENCE(V): a variable/template/mask ($ < { % *), a call or index (NAMEs before the first "(" or "["), or a
 * dotted name with no digit. In: string. Out: bool. Why: detector 13 (SCREEN-05).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function isReference(v) {
  if (v.length > 0 && '$<{%*'.includes(v[0])) return true;
  let first = -1;
  for (let i = 0; i < v.length; i++) {
    if (v[i] === '(' || v[i] === '[') { first = i; break; }
  }
  if (first >= 0 && allNames(v.slice(0, first))) return true;
  if (v.includes('.') && !hasDigit(v) && allNames(v)) return true;
  return false;
}

/**
 * Detector 2: a private key block cut off before its END line, found by hand (spec DETECTORS 2).
 * In: text. Out: [[s, e]] UTF-16 spans. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function findCutPem(text) {
  const spans = [];
  const re = RE.pemHeader;
  let pos = 0;
  while (pos <= text.length) {
    re.lastIndex = pos;
    const h = re.exec(text);
    if (!h) break;
    let p = h.index + h[0].length;
    let count = 0;
    let end = -1;
    for (;;) {
      let q = p;
      for (;;) {
        const c = text[q];
        if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '>' || c === '-') q += 1;
        else if (c === '\\' && text[q + 1] === 'n') q += 2;
        else if (c === '\\' && text[q + 1] === 'r' && text[q + 2] === '\\' && text[q + 3] === 'n') q += 4;
        else break;
      }
      let r = q;
      while (r < text.length) {
        const c = text.charCodeAt(r);
        if (isAlpha(c) || isDigit(c) || c === 43 || c === 47 || c === 61) r++; else break;
      }
      if (r - q < 16) break;
      count += r - q;
      end = r;
      p = r;
    }
    if (count >= 60) {
      spans.push([h.index, end]);
      pos = end;
    } else {
      pos = h.index + 1;
    }
  }
  return spans;
}

/** True for S = [A-Za-z0-9_-]. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function isJwtChar(c) {
  return isW(c) || c === 45;
}

/** The end of the run of S characters that starts at i. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function jwtRunEnd(text, i) {
  while (i < text.length && isJwtChar(text.charCodeAt(i))) i++;
  return i;
}

/**
 * Detector 10: a JWT, found by hand so it is linear (spec DETECTORS 10). In: text. Out: [[s, e]].
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function findJwt(text) {
  const spans = [];
  let pos = 0;
  for (;;) {
    const i = text.indexOf('eyJ', pos);
    if (i === -1) break;
    if (isW(codeAt(text, i - 1))) { pos = i + 1; continue; }
    const j = jwtRunEnd(text, i);
    pos = j;
    if (j - i >= 8 && text[j] === '.') {
      const k = jwtRunEnd(text, j + 1);
      if (k - (j + 1) >= 5 && text[k] === '.') {
        const e = jwtRunEnd(text, k + 1);
        if (e - (k + 1) >= 5) {
          spans.push([i, e]);
          pos = e;
        }
      }
    }
  }
  return spans;
}

/**
 * Detector 13: key = value assignments, matched on the ASCII lower case of the text (spec DETECTORS 13).
 * The "[REDACTED:" test comes before the value scan, a value starting with $ < { % * is refused at once, and where
 * each value ends comes from a table built once (valueEnds), so the scan stays linear (lead ruling fed6e7b).
 * In: text, lower. Out: [[s, e]].
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function findGeneric(text, lower) {
  let valueEnd = null;
  return findAll(RE.generic, lower, (m, start, end) => {
    let run = 0;
    for (let k = start - 1; k >= 0 && run <= 40; k--) {
      const c = lower.charCodeAt(k);
      if ((c >= 97 && c <= 122) || isDigit(c) || c === 95 || c === 46 || c === 45) run++; else break;
    }
    if (run > 40) return null;
    if (text.startsWith(REDACTED_PREFIX, end)) return null;
    // Instant refusals first (they give the same answer as the full checks below, only sooner): a value that
    // starts with $ < { % * is a REFERENCE whatever follows. Lead ruling fed6e7b (SCREEN-14, "token=$" * 28571).
    if (end < text.length && '$<{%*'.includes(text[end])) return null;
    if (valueEnd === null) valueEnd = valueEnds(text);
    const v = valueEnd[end];
    if (v - end < 8) return null; // fewer than 8 UTF-16 units is fewer than 8 code points
    const value = text.slice(end, v);
    if (codePointLength(value) < 8) return null;
    let cut = value.length;
    while (cut > 0 && '.,;:!?'.includes(value[cut - 1])) cut--;
    const trimmed = value.slice(0, cut);
    if (PLACEHOLDERS.has(asciiLower(trimmed))) return null;
    if (isReference(trimmed)) return null;
    if (!looksLikeSecret(trimmed)) return null;
    return { span: [end, v], next: v };
  });
}

/**
 * For every position i, where a detector-13 value starting at i ends (the spec's stop rules), computed once from the
 * right: a stop character, or a backslash whose next character is a stop (not ";"), ends it; a backslash at the very
 * end is taken. In: text. Out: Int32Array of length text.length + 1. Why: lead ruling fed6e7b: following the value
 * scan literally is quadratic on "token=$" * 28571 (SCREEN-14); the answers do not change, only the time.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function valueEnds(text) {
  const n = text.length;
  const out = new Int32Array(n + 1);
  out[n] = n;
  for (let i = n - 1; i >= 0; i--) {
    const c = text[i];
    if (isValueStop(c) || c === ';') out[i] = i;
    else if (c === '\\' && i + 1 < n && isValueStop(text[i + 1])) out[i] = i;
    else out[i] = out[i + 1];
  }
  return out;
}

/**
 * The characters that end a detector-13 value (and that make a backslash before them end it): space, tab, LF,
 * CR, FF, VT, ' and ". In: one character. Out: bool. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function isValueStop(c) {
  return c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === "'" || c === '"';
}

/**
 * Luhn check on a string of digits. In: digits. Out: bool. Why: detector 16 (SCREEN-07).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function luhn(digits) {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Detector 16: card numbers. The span is the LONGEST prefix of the match with 13-19 digits that ends at a group
 * boundary, is grouped like a card, starts with a card network prefix and passes Luhn. In: text. Out: [[s, e]].
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function findCards(text) {
  return findAll(RE.card, text, (m, start, end) => {
    if (!notW(codeAt(text, start - 1))) return null;
    const s = m[0];
    if (!CARD_PREFIX.test(s.replace(/[ -]/g, ''))) return null;
    const ends = [];
    if (notW(codeAt(text, end))) ends.push(s.length);
    for (let i = s.length - 1; i > 0; i--) if (s[i] === ' ' || s[i] === '-') ends.push(i);
    for (const e of ends) {
      const groups = s.slice(0, e).split(/[ -]/);
      const digits = groups.join('');
      if (digits.length < 13 || digits.length > 19) continue;
      let grouped = true;
      for (let g = 0; g < groups.length - 1; g++) if (groups[g].length < 4) { grouped = false; break; }
      if (!grouped || !luhn(digits)) continue;
      return { span: [start, start + e], next: start + e };
    }
    return null;
  });
}

/**
 * Detector 18 check: every number 0-255 with no leading zero, and the address public.
 * In: dotted quad. Out: bool. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function ipv4Public(s) {
  const parts = s.split('.');
  const n = [];
  for (const p of parts) {
    if (p.length > 1 && p[0] === '0') return false;
    const v = parseInt(p, 10);
    if (v > 255) return false;
    n.push(v);
  }
  if (n[0] === 0 || n[0] === 10 || n[0] === 127 || n[0] >= 224) return false;
  if (n[0] === 169 && n[1] === 254) return false;
  if (n[0] === 172 && n[1] >= 16 && n[1] <= 31) return false;
  if (n[0] === 192 && n[1] === 168) return false;
  return n[3] !== 0;
}

/** True when every group is 1 to 4 hex digits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
function hexGroups(groups) {
  for (const g of groups) {
    if (g.length < 1 || g.length > 4) return false;
    for (let i = 0; i < g.length; i++) if (!isHex(g.charCodeAt(i))) return false;
  }
  return true;
}

/**
 * Detector 19 check: a well-formed IPv6 address whose first group is 0x2000-0x3fff (global unicast).
 * In: the match. Out: bool. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function ipv6Global(s) {
  if (s.includes(':::')) return false;
  const dbl = s.indexOf('::');
  let first;
  if (dbl !== -1) {
    if (s.indexOf('::', dbl + 1) !== -1) return false;
    const left = s.slice(0, dbl);
    const right = s.slice(dbl + 2);
    const lg = left === '' ? [] : left.split(':');
    const rg = right === '' ? [] : right.split(':');
    if (lg.length + rg.length > 7) return false;
    if (!hexGroups(lg) || !hexGroups(rg)) return false;
    first = lg.length === 0 ? 0 : parseInt(lg[0], 16);
  } else {
    const groups = s.split(':');
    if (groups.length !== 8 || !hexGroups(groups)) return false;
    first = parseInt(groups[0], 16);
  }
  return first >= 0x2000 && first <= 0x3fff;
}

/**
 * Accept helper for detectors whose guard is "before is not W" (and optionally "after is not W").
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function boundary(text, start, end, needAfter) {
  return notW(codeAt(text, start - 1)) && (!needAfter || notW(codeAt(text, end)));
}

/**
 * The 19 detectors in priority order (spec DETECTORS). Each find(text, lower) returns UTF-16 spans.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
const DETECTORS = [
  { num: 1, category: 'secret', label: 'pem_private_key', find: t => findAll(RE.pem, t, (m, s, e) => ({ span: [s, e] })) },
  { num: 2, category: 'secret', label: 'pem_private_key', find: t => findCutPem(t) },
  {
    num: 3, category: 'secret', label: 'openai_style_api_key',
    find: t => findAll(RE.openai, t, (m, s, e) => (boundary(t, s, e, false) && hasDigit(m[0]) ? { span: [s, e] } : null))
  },
  {
    num: 4, category: 'secret', label: 'stripe_style_api_key',
    find: t => findAll(RE.stripe, t, (m, s, e) => (boundary(t, s, e, true) ? { span: [s, e] } : null))
  },
  {
    num: 5, category: 'secret', label: 'aws_access_key_id',
    find: t => findAll(RE.aws, t, (m, s, e) => (boundary(t, s, e, true) ? { span: [s, e] } : null))
  },
  {
    num: 6, category: 'secret', label: 'github_token',
    find: t => findAll(RE.github, t, (m, s, e) => (boundary(t, s, e, true) ? { span: [s, e] } : null))
  },
  {
    num: 7, category: 'secret', label: 'slack_token',
    find: t => findAll(RE.slack, t, (m, s, e) => (boundary(t, s, e, true) ? { span: [s, e] } : null))
  },
  {
    num: 8, category: 'secret', label: 'google_api_key',
    find: t => findAll(RE.google, t, (m, s, e) =>
      (boundary(t, s, e, true) && codeAt(t, e) !== 45 ? { span: [s, e] } : null))
  },
  {
    num: 9, category: 'secret', label: 'webhook_signing_secret',
    find: t => findAll(RE.whsec, t, (m, s, e) => (boundary(t, s, e, false) ? { span: [s, e] } : null))
  },
  { num: 10, category: 'secret', label: 'jwt', find: t => findJwt(t) },
  {
    num: 11, category: 'secret', label: 'bearer_token',
    find: t => findAll(RE.bearer, t, (m, s, e) => {
      if (!boundary(t, s, e, false)) return null;
      const g = m[1];
      if (!hasDigit(g) && camelPlaces(g) < 2) return null;
      return { span: [e - g.length, e] };
    })
  },
  {
    num: 12, category: 'secret', label: 'url_credentials',
    find: t => findAll(RE.url, t, (m, s, e) => {
      const g = m[1];
      if (g.startsWith(REDACTED_PREFIX) || PLACEHOLDERS.has(asciiLower(g))) return null;
      return { span: [e - 1 - g.length, e - 1] };
    })
  },
  { num: 13, category: 'secret', label: 'generic_key_value_assignment', find: (t, lower) => findGeneric(t, lower) },
  {
    num: 14, category: 'pii', label: 'email_address',
    find: t => findAll(RE.email, t, (m, s, e) => {
      if (!boundary(t, s, e, true)) return null;
      let k = s - 1;
      while (k >= 0 && !'/@ \t\r\n'.includes(t[k])) k--;
      if (k >= 2 && t[k] === '/' && t[k - 1] === '/' && t[k - 2] === ':') return null;
      return { span: [s, e] };
    })
  },
  {
    num: 15, category: 'pii', label: 'phone_number',
    find: t => findAll(RE.phone, t, (m, s, e) =>
      (!isDigit(codeAt(t, s - 1)) && !isDigit(codeAt(t, e)) ? { span: [s, e] } : null))
  },
  { num: 16, category: 'pii', label: 'credit_card_number', find: t => findCards(t) },
  {
    num: 17, category: 'pii', label: 'ssn',
    find: t => findAll(RE.ssn, t, (m, s, e) => {
      const b = codeAt(t, s - 1);
      const a = codeAt(t, e);
      if (!(notW(b) && b !== 45 && notW(a) && a !== 45)) return null;
      const [g1, g2, g3] = m[0].split('-');
      if (g1 === '000' || g1 === '666' || g1[0] === '9' || g2 === '00' || g3 === '0000') return null;
      return { span: [s, e] };
    })
  },
  {
    num: 18, category: 'pii', label: 'ip_address',
    find: t => findAll(RE.ipv4, t, (m, s, e) => {
      const b = codeAt(t, s - 1);
      const a = codeAt(t, e);
      if (!(notW(b) && b !== 46 && notW(a))) return null;
      if (a === 46 && isDigit(codeAt(t, e + 1))) return null;
      return ipv4Public(m[0]) ? { span: [s, e] } : null;
    })
  },
  {
    num: 19, category: 'pii', label: 'ip_address',
    find: t => findAll(RE.ipv6, t, (m, s, e) => {
      const b = codeAt(t, s - 1);
      const a = codeAt(t, e);
      if (!(b === -1 || !(isW(b) || b === 58 || b === 46))) return null;
      if (!(a === -1 || !(isW(a) || a === 58))) return null;
      return ipv6Global(m[0]) ? { span: [s, e] } : null;
    })
  }
];

/* ------------------------------------------------------------------ the screener */

/**
 * Screener: holds the HMAC key for value_hash and the size limit. Build it with newScreener().
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only; never logs the key.
 */
class Screener {
  /**
   * In: hashKey (Buffer | Uint8Array | string of at least 32 bytes, or null/undefined for no key), maxBytes.
   * Out: a screener. Throws ScreeningError("invalid_hash_key") for a key under 32 bytes (SCREEN-12, fail closed).
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  constructor(hashKey = null, maxBytes = DEFAULT_MAX_BYTES) {
    let key = null;
    if (hashKey !== null && hashKey !== undefined) {
      key = typeof hashKey === 'string' ? Buffer.from(hashKey, 'utf8') : Buffer.from(hashKey);
      if (key.length < 32) throw new ScreeningError('invalid_hash_key');
    }
    Object.defineProperty(this, '_hashKey', { value: key, enumerable: false });
    this.maxBytes = maxBytes;
  }

  /**
   * value_hash: lower-case hex HMAC-SHA256(hash_key, UTF-8 of value), or null without a key.
   * In: matched text. Out: string | null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  valueHash(value) {
    if (!this._hashKey) return null;
    return crypto.createHmac('sha256', this._hashKey).update(value, 'utf8').digest('hex');
  }

  /**
   * scan_text(text, categories): every finding of the detectors whose category is asked for, combined so no
   * character is in two findings (earliest start, then longest span, then lower detector number).
   * In: text, categories (default ["secret", "pii"]). Out: [{category, label, start, end, preview, value_hash,
   * encoded: false}] ordered by start, positions in code points. Why: SCREEN-02..SCREEN-11.
   * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  scanText(text, categories = ['secret', 'pii']) {
    const wanted = new Set(categories);
    const lower = asciiLower(text);
    const map = utf16ToCpMap(text);
    const toCp = i => (map ? map[i] : i);
    const candidates = [];
    for (const d of DETECTORS) {
      if (!wanted.has(d.category)) continue;
      for (const [s, e] of d.find(text, lower)) {
        candidates.push({ d, s16: s, e16: e, start: toCp(s), end: toCp(e) });
      }
    }
    candidates.sort((x, y) => (x.start - y.start) || ((y.end - y.start) - (x.end - x.start)) || (x.d.num - y.d.num));
    const findings = [];
    let lastEnd = -1;
    for (const c of candidates) {
      if (c.start < lastEnd) continue;
      const value = text.slice(c.s16, c.e16);
      findings.push({
        category: c.d.category, label: c.d.label, start: c.start, end: c.end,
        preview: mask(value), value_hash: this.valueHash(value), encoded: false
      });
      lastEnd = c.end;
    }
    return findings;
  }

  /**
   * redact_text(text, findings): each finding's span replaced by "[REDACTED:" + label + "]", in ONE left-to-right
   * pass. Findings with no position (start -1) are skipped. In: text, findings (code point positions).
   * Out: text. Why: SCREEN-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  redactText(text, findings) {
    return redactText(text, findings);
  }

  /**
   * screen_text(text, mode, categories): the entry point; the steps run in the spec's order and the first that
   * answers ends the call. In: text, mode ("reject" default | "strip"), categories (default ["secret", "pii"]).
   * Out: {ok: true, status: 200, text, findings} or {ok: false, error, status[, findings]} (never holds `text`).
   * Any exception inside the scan or hidden check is {ok: false, error: "screening_failed", status: 500}.
   * Why: SCREEN-09, SCREEN-10, SCREEN-13, SCREEN-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
   */
  screenText(text, mode = 'reject', categories = ['secret', 'pii']) {
    if (typeof text !== 'string' || !text.isWellFormed()) return { ok: false, error: 'invalid_text', status: 400 };
    if (mode !== 'reject' && mode !== 'strip') return { ok: false, error: 'invalid_mode', status: 400 };
    if (!Array.isArray(categories) || categories.length === 0 || !categories.every(c => VALID_CATEGORIES.has(c))) {
      return { ok: false, error: 'invalid_categories', status: 400 };
    }
    if (Buffer.byteLength(text, 'utf8') > this.maxBytes) return { ok: false, error: 'text_too_large', status: 413 };
    try {
      const F = this.scanText(text, categories);
      if (mode === 'reject' && F.length > 0) {
        return { ok: false, error: 'secrets_or_pii_detected', status: 422, findings: F };
      }
      const out = F.length > 0 ? redactText(text, F) : text;
      if (mode === 'strip' && F.length > 0) {
        const F2 = this.scanText(out, categories);
        if (F2.length > 0) {
          return {
            ok: false, error: 'secrets_or_pii_detected', status: 422,
            findings: F.concat(F2.map(f => ({ ...f, start: -1, end: -1 })))
          };
        }
      }
      if (out.includes('\\')) {
        const R = resolveEscapes(out);
        const H = [];
        if (R.text !== out) {
          for (const f of this.scanText(R.text, categories)) H.push({ ...f, start: -1, end: -1, encoded: true });
        }
        if (R.unresolved) {
          H.push({
            category: 'secret', label: 'unresolved_escape', start: -1, end: -1, preview: '***', value_hash: null,
            encoded: true
          });
        }
        if (H.length > 0) return { ok: false, error: 'secrets_or_pii_detected', status: 422, findings: F.concat(H) };
      }
      return { ok: true, status: 200, text: out, findings: F };
    } catch (err) {
      return { ok: false, error: 'screening_failed', status: 500 };
    }
  }

  /** mask(value), see the module function. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  mask(value) {
    return mask(value);
  }

  /** resolve_escapes(text), see the module function. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing. */
  resolveEscapes(text) {
    return resolveEscapes(text);
  }
}

/**
 * redact_text(text, findings): one left-to-right pass replacing each finding's span (code points) by
 * "[REDACTED:" + label + "]". In: text, findings. Out: text. Why: SCREEN-10.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function redactText(text, findings) {
  const placed = findings.filter(f => f.start >= 0).slice().sort((a, b) => a.start - b.start);
  if (placed.length === 0) return text;
  let cpToU16 = null;
  if (/[\uD800-\uDFFF]/.test(text)) {
    cpToU16 = [];
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      const isLowAfterHigh = c >= 0xdc00 && c <= 0xdfff && i > 0 &&
        text.charCodeAt(i - 1) >= 0xd800 && text.charCodeAt(i - 1) <= 0xdbff;
      if (!isLowAfterHigh) cpToU16.push(i);
    }
    cpToU16.push(text.length);
  }
  const at = cp => (cpToU16 ? cpToU16[cp] : cp);
  const parts = [];
  let last = 0;
  for (const f of placed) {
    const s = at(f.start);
    if (s < last) continue;
    parts.push(text.slice(last, s), REDACTED_PREFIX + f.label + ']');
    last = at(f.end);
  }
  parts.push(text.slice(last));
  return parts.join('');
}

/**
 * new_screener(hash_key = none, max_bytes = 1048576). In: hashKey, maxBytes. Out: Screener. Throws
 * ScreeningError("invalid_hash_key") for a key under 32 bytes. Why: spec ENDPOINTS / FUNCTIONS.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches memory only.
 */
function newScreener(hashKey = null, maxBytes = DEFAULT_MAX_BYTES) {
  return new Screener(hashKey, maxBytes);
}

module.exports = { newScreener, Screener, ScreeningError, mask, resolveEscapes, redactText };
