/**
 * Secret & PII screening (docs/specs/secret_pii_screening.md): finds secrets (API keys, tokens, private keys,
 * passwords in URLs and in assignments) and personal data (email addresses, phone numbers, card numbers, IP
 * addresses, US social security numbers) in a text BEFORE it is stored, logged or shared, and either refuses the text
 * (mode "reject", the default) or replaces each match with "[REDACTED:<label>]" (mode "strip"). A hidden check
 * resolves JSON escapes so a secret behind A-style escapes is refused too. Nothing is stored.
 *
 * Exports: ScreenError, Finding and the result types, Screener (screenText, scanText, redactText), newScreener,
 * mask, resolveEscapes, looksLikeSecret.
 *
 * Positions: the detectors run on the JavaScript string (UTF-16 units); every start/end returned is converted to
 * Unicode code points, as the spec requires. The regexes use no flags but "g" (for lastIndex): no i, no u, no m.
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (six new systems). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing outside the call (no network, no files, no database, no money). Never logs a text, a matched
 * value or the hash key.
 */
import { createHmac } from 'crypto';

/** A finding (spec scan_text). start/end count code points; -1 for a finding that has no place in the text. */
export interface Finding {
  category: 'secret' | 'pii';
  label: string;
  start: number;
  end: number;
  preview: string;
  value_hash: string | null;
  encoded: boolean;
}

/** screen_text's accepted answer. */
export interface ScreenOk {
  ok: true;
  status: 200;
  text: string;
  findings: Finding[];
}

/** screen_text's refusal: never carries `text`. */
export interface ScreenRefusal {
  ok: false;
  error: string;
  status: number;
  findings?: Finding[];
}

/**
 * Thrown by the Screener constructor: code "invalid_hash_key" for a key under 32 bytes (fail closed). The message
 * never holds the key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export class ScreenError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'ScreenError';
  }
}

/* ------------------------------------------------------------------ character helpers */

/** W = [A-Za-z0-9_]; undefined (no character) is not W. */
function isW(c: string | undefined): boolean {
  if (c === undefined) return false;
  const x = c.charCodeAt(0);
  return (x >= 48 && x <= 57) || (x >= 65 && x <= 90) || (x >= 97 && x <= 122) || x === 95;
}

/** A digit 0-9 (ASCII only). */
function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= '0' && c <= '9';
}

/** ASCII lower case: A-Z to a-z, nothing else, so positions stay the same. */
function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/**
 * mask(value): n = its code points; n < 16 -> "*" x n; else its first 2 characters, "*" x (n - 4), its last 2.
 * In: the matched value. Out: the preview. Why: spec mask (SCREEN-12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
export function mask(value: string): string {
  const cps = Array.from(value);
  const n = cps.length;
  if (n < 16) return '*'.repeat(n);
  return cps.slice(0, 2).join('') + '*'.repeat(n - 4) + cps.slice(n - 2).join('');
}

/**
 * looks_like_secret(v): a digit 0-9; or a character below U+0080 outside [A-Za-z0-9]; or at least 2 places where a
 * letter a-z is directly followed by a letter A-Z. A character at or above U+0080 passes none of the three.
 * In: the value. Out: true or false. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function looksLikeSecret(v: string): boolean {
  return looksLikeSecretAt(v, 0, v.length);
}

/**
 * looks_like_secret on t[from, to) without copying it; stops at the first hit. In: text, range. Out: true or false.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function looksLikeSecretAt(t: string, from: number, to: number): boolean {
  let pairs = 0;
  for (let i = from; i < to; i++) {
    const x = t.charCodeAt(i);
    if (x >= 48 && x <= 57) return true;
    const alpha = (x >= 65 && x <= 90) || (x >= 97 && x <= 122);
    if (x < 0x80 && !alpha) return true;
    if (x >= 97 && x <= 122 && i + 1 < to) {
      const y = t.charCodeAt(i + 1);
      if (y >= 65 && y <= 90 && ++pairs >= 2) return true;
    }
  }
  return false;
}

/** The longest PLACEHOLDER: a longer V is never one, so it is not copied to be compared. */
const MAX_PLACEHOLDER = 15;

/** PLACEHOLDERS (spec): compared with the ASCII lower case of a value. */
const PLACEHOLDERS = new Set(['changeme', 'change_me', 'your_key_here', 'your-key-here', 'xxx', 'xxxx', 'xxxxx', 'redacted',
  'todo', 'example', 'placeholder', 'secret', 'password', 'insert_key_here', 'none', 'null', 'n/a', 'na',
  '<your-password>', '<your-key>', 'fillmein']);

/** A letter A-Z a-z or "_" (a NAME's first character). */
function isNameStart(c: string): boolean {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c === '_';
}

/**
 * Whether t[from, to), split at ".", is NAMEs only (a NAME: a letter A-Z a-z or "_", then letters, digits 0-9 and
 * "_"). With noDigits, any digit fails it too. Written as a loop that stops at the first failure (spec MATCHING).
 * In: text, range, noDigits. Out: true or false. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function namesAt(t: string, from: number, to: number, noDigits: boolean): boolean {
  let partStart = true;
  for (let i = from; i < to; i++) {
    const c = t[i];
    if (c === '.') {
      if (partStart) return false;
      partStart = true;
    } else if (isNameStart(c)) {
      partStart = false;
    } else if (isDigit(c) && !partStart && !noDigits) {
      partStart = false;
    } else {
      return false;
    }
  }
  return !partStart;
}

/**
 * REFERENCE(V) on t[from, to): V says where a secret comes from: it starts with $ < { % *; or holds "(" or "[" and
 * what stands before the first of them is NAMEs split at "."; or it holds ".", no digit 0-9, and is NAMEs split at
 * ".". The search for "(" or "[" stops at the first character that no NAME or "." can hold, because such a
 * character before the bracket already makes the second rule false. In: text, range. Out: true or false.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function isReferenceAt(t: string, from: number, to: number): boolean {
  if (to > from && '$<{%*'.includes(t[from])) return true;
  for (let i = from; i < to; i++) {
    const c = t[i];
    if (c === '(' || c === '[') {
      if (namesAt(t, from, i, false)) return true;
      break;
    }
    if (!(isNameStart(c) || isDigit(c) || c === '.')) break;
  }
  let dot = false;
  for (let i = from; i < to; i++) {
    if (t[i] === '.') {
      dot = true;
      break;
    }
    if (!isNameStart(t[i])) return false;
  }
  return dot && namesAt(t, from, to, true);
}

/** CARD PREFIX on the digits (spec). */
const CARD_PREFIX = /^(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])/;

/** Luhn: from the last digit leftwards, double every second digit (minus 9 when over 9); the sum is a multiple of 10. */
function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/* ------------------------------------------------------------------ escapes */

/** An ESCAPE: \uXXXX or a backslash followed by one of " \ / b f n r t. */
const ESCAPE = /\\(?:u[0-9A-Fa-f]{4}|["\\/bfnrt])/;

/**
 * One left-to-right pass that replaces every ESCAPE (a high surrogate escape directly followed by a low surrogate
 * escape becomes the one character; any other surrogate U+FFFD). In: text. Out: the text after the pass.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function escapePass(t: string): string {
  const out: string[] = [];
  const hex4 = (i: number) => /^[0-9A-Fa-f]{4}$/.test(t.slice(i, i + 4)) ? parseInt(t.slice(i, i + 4), 16) : -1;
  let i = 0;
  while (i < t.length) {
    const c = t[i];
    if (c !== '\\' || i + 1 >= t.length) {
      out.push(c);
      i++;
      continue;
    }
    const n = t[i + 1];
    if (n === 'u') {
      const code = hex4(i + 2);
      if (code >= 0) {
        if (code >= 0xd800 && code <= 0xdbff && t[i + 6] === '\\' && t[i + 7] === 'u') {
          const low = hex4(i + 8);
          if (low >= 0xdc00 && low <= 0xdfff) {
            out.push(String.fromCharCode(code, low));
            i += 12;
            continue;
          }
        }
        out.push(code >= 0xd800 && code <= 0xdfff ? '�' : String.fromCharCode(code));
        i += 6;
        continue;
      }
    }
    const simple: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
    if (Object.prototype.hasOwnProperty.call(simple, n)) {
      out.push(simple[n]);
      i += 2;
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

/**
 * resolve_escapes(text): repeats the escape pass while the text holds an ESCAPE, at most 8 times.
 * In: text. Out: {text, unresolved} (unresolved: an ESCAPE is left after the 8th pass). Why: spec ESCAPES
 * (SCREEN-13). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function resolveEscapes(text: string): { text: string; unresolved: boolean } {
  let t = text;
  for (let pass = 0; pass < 8 && ESCAPE.test(t); pass++) t = escapePass(t);
  return { text: t, unresolved: ESCAPE.test(t) };
}

/* ------------------------------------------------------------------ scanning */

/** A candidate, in UTF-16 units. */
interface Candidate {
  start: number;
  end: number;
  detector: number;
  label: string;
  category: 'secret' | 'pii';
}

/**
 * Per-text tables computed once in linear time, so no guard or value scan rescans the text: the nearest URL-ish
 * delimiter before each position (email guard), the next stop character (detector 13's value), and the start of the
 * run of . , ; : ! ? ending at each position (detector 13's V). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
class TextTables {
  private delim: Int32Array | null = null;
  private stop: Int32Array | null = null;
  private punct: Int32Array | null = null;
  private cps: Int32Array | null = null;

  /** In: the text and its ASCII lower case (LOWER). */
  constructor(private readonly t: string, readonly lower: string) {}

  /** The nearest index < i holding "/", "@", space, tab, CR or LF, or -1. */
  delimBefore(i: number): number {
    if (this.delim === null) {
      const d = new Int32Array(this.t.length + 1);
      let last = -1;
      for (let k = 0; k <= this.t.length; k++) {
        d[k] = last;
        const c = this.t[k];
        if (c === '/' || c === '@' || c === ' ' || c === '\t' || c === '\r' || c === '\n') last = k;
      }
      this.delim = d;
    }
    return this.delim[i];
  }

  /** The end of detector 13's value starting at i. */
  valueEnd(i: number): number {
    if (this.stop === null) {
      const t = this.t;
      const n = t.length;
      const s = new Int32Array(n + 1);
      s[n] = n;
      const ws = (c: string | undefined) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v';
      for (let k = n - 1; k >= 0; k--) {
        const c = t[k];
        const stops = ws(c) || c === "'" || c === '"' || c === ';' ||
          (c === '\\' && k + 1 < n && (ws(t[k + 1]) || t[k + 1] === "'" || t[k + 1] === '"'));
        s[k] = stops ? k : s[k + 1];
      }
      this.stop = s;
    }
    return this.stop[i];
  }

  /** The number of code points in t[from, to), from a prefix table built once. */
  cpCount(from: number, to: number): number {
    if (this.cps === null) {
      const c = new Int32Array(this.t.length + 1);
      for (let i = 0; i < this.t.length; i++) {
        const x = this.t.charCodeAt(i);
        const pairedLow = x >= 0xdc00 && x <= 0xdfff && i > 0 && this.t.charCodeAt(i - 1) >= 0xd800 && this.t.charCodeAt(i - 1) <= 0xdbff;
        c[i + 1] = c[i] + (pairedLow ? 0 : 1);
      }
      this.cps = c;
    }
    return this.cps[to] - this.cps[from];
  }

  /** The start of the run of . , ; : ! ? that ends at e. */
  punctRunStart(e: number): number {
    if (this.punct === null) {
      const p = new Int32Array(this.t.length + 1);
      p[0] = 0;
      for (let k = 1; k <= this.t.length; k++) p[k] = '.,;:!?'.includes(this.t[k - 1]) ? p[k - 1] : k;
      this.punct = p;
    }
    return this.punct[e];
  }
}

/** One regex detector: its regex, guard, check and span rule. accept() returns [start, end, nextPos] or null. */
interface RegexDetector {
  n: number;
  label: string;
  category: 'secret' | 'pii';
  re: RegExp;
  lower?: boolean;
  accept: (t: string, m: RegExpExecArray, tables: TextTables) => [number, number, number] | null;
}

/** Guard helpers on a match: the characters before and after it (undefined at the ends of the text). */
const before = (t: string, m: RegExpExecArray) => (m.index > 0 ? t[m.index - 1] : undefined);
const after = (t: string, m: RegExpExecArray) => {
  const e = m.index + m[0].length;
  return e < t.length ? t[e] : undefined;
};
const whole = (m: RegExpExecArray): [number, number, number] => [m.index, m.index + m[0].length, m.index + m[0].length];
/** Span = capture group 1, which ends the match or is followed only by `tail` characters. */
const group1 = (m: RegExpExecArray, tail: number): [number, number, number] => {
  const e = m.index + m[0].length;
  return [e - tail - m[1].length, e - tail, e];
};

/**
 * Detector 16's span: the LONGEST prefix of m with 13-19 digits that ends at the end of m (after not W) or just
 * before a space or "-" inside m, is grouped like a card, and whose digits pass the CARD PREFIX and Luhn.
 * In: text, match. Out: [start, end, end] or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function cardSpan(t: string, m: RegExpExecArray): [number, number, number] | null {
  const s = m[0];
  if (!CARD_PREFIX.test(s.replace(/[ -]/g, ''))) return null;
  for (let len = s.length; len > 0; len--) {
    const endsAtEnd = len === s.length;
    if (endsAtEnd ? isW(after(t, m)) : !(s[len] === ' ' || s[len] === '-')) continue;
    const prefix = s.slice(0, len);
    if (prefix.endsWith(' ') || prefix.endsWith('-')) continue;
    const digits = prefix.replace(/[ -]/g, '');
    if (digits.length < 13 || digits.length > 19) continue;
    const groups = prefix.split(/[ -]/);
    if (groups.slice(0, -1).some((g) => g.length < 4)) continue;
    if (!luhn(digits)) continue;
    return [m.index, m.index + len, m.index + len];
  }
  return null;
}

/** IPv4 check: numbers 0-255 without a leading zero, public, and not ending in .0. */
function ipv4Ok(s: string): boolean {
  const parts = s.split('.');
  const nums: number[] = [];
  for (const p of parts) {
    if (p.length > 1 && p[0] === '0') return false;
    const v = Number(p);
    if (v > 255) return false;
    nums.push(v);
  }
  const [a, b2] = nums;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if ((a === 169 && b2 === 254) || (a === 172 && b2 >= 16 && b2 <= 31) || (a === 192 && b2 === 168)) return false;
  return nums[3] !== 0;
}

/** IPv6 check: "::" at most once and never ":::"; group counts; 1-4 hex digits each; first group 0x2000-0x3fff. */
function ipv6Ok(s: string): boolean {
  if (s.includes(':::')) return false;
  const dbl = s.split('::');
  if (dbl.length > 2) return false;
  const groupsOf = (part: string) => (part === '' ? [] : part.split(':'));
  let groups: string[];
  if (dbl.length === 2) {
    const left = groupsOf(dbl[0]);
    const right = groupsOf(dbl[1]);
    if (left.length + right.length > 7) return false;
    groups = [...left, ...right];
    if (groups.some((g) => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
    const first = left.length ? parseInt(left[0], 16) : 0;
    return first >= 0x2000 && first <= 0x3fff;
  }
  groups = s.split(':');
  if (groups.length !== 8 || groups.some((g) => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
  const first = parseInt(groups[0], 16);
  return first >= 0x2000 && first <= 0x3fff;
}

/** The regex detectors (spec DETECTORS), in priority order; 2 and 10 are procedures below. */
const DETECTORS: RegexDetector[] = [
  { n: 1, label: 'pem_private_key', category: 'secret',
    re: /-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\r?\n)?[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----/g,
    accept: (_t, m) => whole(m) },
  { n: 3, label: 'openai_style_api_key', category: 'secret', re: /sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]/g,
    accept: (t, m) => (!isW(before(t, m)) && /[0-9]/.test(m[0]) ? whole(m) : null) },
  { n: 4, label: 'stripe_style_api_key', category: 'secret', re: /[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}/g,
    accept: (t, m) => (!isW(before(t, m)) && !isW(after(t, m)) ? whole(m) : null) },
  { n: 5, label: 'aws_access_key_id', category: 'secret', re: /A[KS]IA[0-9A-Z]{16}/g,
    accept: (t, m) => (!isW(before(t, m)) && !isW(after(t, m)) ? whole(m) : null) },
  { n: 6, label: 'github_token', category: 'secret', re: /gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}/g,
    accept: (t, m) => (!isW(before(t, m)) && !isW(after(t, m)) ? whole(m) : null) },
  { n: 7, label: 'slack_token', category: 'secret', re: /xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]/g,
    accept: (t, m) => (!isW(before(t, m)) && !isW(after(t, m)) ? whole(m) : null) },
  { n: 8, label: 'google_api_key', category: 'secret', re: /AIza[0-9A-Za-z_-]{35}/g,
    accept: (t, m) => (!isW(before(t, m)) && !isW(after(t, m)) && after(t, m) !== '-' ? whole(m) : null) },
  { n: 9, label: 'webhook_signing_secret', category: 'secret', re: /whsec_[A-Za-z0-9+/=]{16,500}/g,
    accept: (t, m) => (!isW(before(t, m)) ? whole(m) : null) },
  { n: 11, label: 'bearer_token', category: 'secret', re: /[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})/g,
    accept: (t, m) => {
      if (isW(before(t, m))) return null;
      const g = m[1];
      let pairs = 0;
      for (let i = 0; i + 1 < g.length; i++) if (g[i] >= 'a' && g[i] <= 'z' && g[i + 1] >= 'A' && g[i + 1] <= 'Z') pairs++;
      return /[0-9]/.test(g) || pairs >= 2 ? group1(m, 0) : null;
    } },
  { n: 12, label: 'url_credentials', category: 'secret', re: /[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@/g,
    accept: (_t, m) => (!m[1].startsWith('[REDACTED:') && !PLACEHOLDERS.has(asciiLower(m[1])) ? group1(m, 1) : null) },
  { n: 13, label: 'generic_key_value_assignment', category: 'secret', lower: true,
    re: /(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key|credentials?|token)(?:\\?["'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?["'])?/g,
    accept: (t, m, tables) => {
      // the guard: the run of [a-z0-9_.-] just before m (in LOWER) is at most 40 long
      let run = 0;
      for (let k = m.index - 1; k >= 0 && run <= 40; k--) {
        if (!/[a-z0-9_.-]/.test(tables.lower[k])) break;
        run++;
      }
      if (run > 40) return null;
      const vs = m.index + m[0].length;
      if (t.startsWith('[REDACTED:', vs)) return null;
      const ve = tables.valueEnd(vs);
      if (tables.cpCount(vs, ve) < 8) return null;
      // V = the value without its trailing . , ; : ! ? Every test below stops early, so a long value that is not a
      // candidate (pos then moves only one character) is never scanned to its end again and again.
      const vEnd = Math.max(vs, tables.punctRunStart(ve));
      if (vEnd - vs <= MAX_PLACEHOLDER && PLACEHOLDERS.has(asciiLower(t.slice(vs, vEnd)))) return null;
      if (isReferenceAt(t, vs, vEnd) || !looksLikeSecretAt(t, vs, vEnd)) return null;
      return [vs, ve, ve];
    } },
  { n: 14, label: 'email_address', category: 'pii', re: /[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}/g,
    accept: (t, m, tables) => {
      if (isW(before(t, m)) || isW(after(t, m))) return null;
      const k = tables.delimBefore(m.index);
      if (k >= 2 && t.slice(k - 2, k + 1) === '://') return null;
      return whole(m);
    } },
  { n: 15, label: 'phone_number', category: 'pii',
    re: /(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}/g,
    accept: (t, m) => (!isDigit(before(t, m)) && !isDigit(after(t, m)) ? whole(m) : null) },
  { n: 16, label: 'credit_card_number', category: 'pii', re: /[0-9](?:[ -]?[0-9]){12,18}/g,
    accept: (t, m) => (isW(before(t, m)) ? null : cardSpan(t, m)) },
  { n: 17, label: 'ssn', category: 'pii', re: /[0-9]{3}-[0-9]{2}-[0-9]{4}/g,
    accept: (t, m) => {
      const b = before(t, m);
      const a = after(t, m);
      if (isW(b) || b === '-' || isW(a) || a === '-') return null;
      const [g1, g2, g3] = m[0].split('-');
      if (g1 === '000' || g1 === '666' || g1[0] === '9' || g2 === '00' || g3 === '0000') return null;
      return whole(m);
    } },
  { n: 18, label: 'ip_address', category: 'pii', re: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/g,
    accept: (t, m) => {
      const b = before(t, m);
      const a = after(t, m);
      const e = m.index + m[0].length;
      if (isW(b) || b === '.' || isW(a) || (a === '.' && isDigit(t[e + 1]))) return null;
      return ipv4Ok(m[0]) ? whole(m) : null;
    } },
  { n: 19, label: 'ip_address', category: 'pii', re: /[0-9A-Fa-f:]{2,39}/g,
    accept: (t, m) => {
      const b = before(t, m);
      const a = after(t, m);
      if (b !== undefined && (isW(b) || b === ':' || b === '.')) return null;
      if (a !== undefined && (isW(a) || a === ':')) return null;
      return ipv6Ok(m[0]) ? whole(m) : null;
    } },
];

/**
 * find_all for one regex detector (spec MATCHING): the leftmost match at or after pos; an accepted match is a
 * candidate and pos moves to its end (or the detector's own next position); otherwise pos = its start + 1.
 * In: detector, text, LOWER text, tables. Out: candidates (UTF-16). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 */
function findAll(d: RegexDetector, text: string, lower: string, tables: TextTables): Candidate[] {
  const subject = d.lower ? lower : text;
  const re = new RegExp(d.re.source, 'g');
  const out: Candidate[] = [];
  let pos = 0;
  while (pos <= subject.length) {
    re.lastIndex = pos;
    const m = re.exec(subject);
    if (m === null) break;
    const res = d.accept(text, m, tables);
    if (res) {
      out.push({ start: res[0], end: res[1], detector: d.n, label: d.label, category: d.category });
      pos = res[2];
    } else {
      pos = m.index + 1;
    }
  }
  return out;
}

/** The PEM header regex shared by detector 2. */
const PEM_HEADER = /-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----/g;

/**
 * Detector 2: a private key block cut off before its END line, found by hand (spec): after each header, runs of
 * [A-Za-z0-9+/=] of at least 16 characters, separated by spaces, tabs, CR, LF, ">", "-", "\n" or "\r\n" escapes;
 * 60 run characters or more make a candidate from the header to the end of the last run.
 * In: text. Out: candidates. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function pemCutOff(t: string): Candidate[] {
  const out: Candidate[] = [];
  const re = new RegExp(PEM_HEADER.source, 'g');
  const isRun = (c: string) => /[A-Za-z0-9+/=]/.test(c);
  let pos = 0;
  while (pos <= t.length) {
    re.lastIndex = pos;
    const h = re.exec(t);
    if (h === null) break;
    let p = h.index + h[0].length;
    let count = 0;
    let end = -1;
    for (;;) {
      let q = p;
      for (;;) {
        const c = t[q];
        if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '>' || c === '-') q += 1;
        else if (c === '\\' && t[q + 1] === 'n') q += 2;
        else if (c === '\\' && t[q + 1] === 'r' && t[q + 2] === '\\' && t[q + 3] === 'n') q += 4;
        else break;
      }
      let r = q;
      while (r < t.length && isRun(t[r])) r++;
      if (r - q < 16) break;
      count += r - q;
      end = r;
      p = r;
    }
    if (count >= 60) {
      out.push({ start: h.index, end, detector: 2, label: 'pem_private_key', category: 'secret' });
      pos = end;
    } else {
      pos = h.index + 1;
    }
  }
  return out;
}

/**
 * Detector 10: a JWT, found by hand so it is linear (spec): "eyJ" not after a W character, a run of S characters
 * (8 or more from the "eyJ"), ".", a run of 5+, ".", a run of 5+. In: text. Out: candidates.
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
function jwt(t: string): Candidate[] {
  const out: Candidate[] = [];
  const isS = (c: string | undefined) => c !== undefined && (isW(c) || c === '-');
  const runEnd = (i: number) => {
    while (i < t.length && isS(t[i])) i++;
    return i;
  };
  let pos = 0;
  for (;;) {
    const i = t.indexOf('eyJ', pos);
    if (i < 0) break;
    if (i > 0 && isW(t[i - 1])) {
      pos = i + 1;
      continue;
    }
    const j = runEnd(i);
    pos = j;
    if (j - i >= 8 && t[j] === '.') {
      const k = runEnd(j + 1);
      if (k - (j + 1) >= 5 && t[k] === '.') {
        const e = runEnd(k + 1);
        if (e - (k + 1) >= 5) {
          out.push({ start: i, end: e, detector: 10, label: 'jwt', category: 'secret' });
          pos = e;
        }
      }
    }
  }
  return out;
}

/* ------------------------------------------------------------------ screener */

/**
 * The screener. Construction fails closed (ScreenError "invalid_hash_key") for a hash key under 32 bytes; without a
 * key every value_hash is null. Why: spec new_screener (SCREEN-12). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches nothing.
 */
export class Screener {
  private readonly hashKey: Buffer | null;
  readonly maxBytes: number;

  /**
   * In: hash key (bytes or text; null / undefined for none), max_bytes (default 1048576). Out: the screener.
   * Throws ScreenError("invalid_hash_key"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  constructor(hashKey?: Uint8Array | string | null, maxBytes = 1048576) {
    if (hashKey === undefined || hashKey === null) {
      this.hashKey = null;
    } else {
      const key = typeof hashKey === 'string' ? Buffer.from(hashKey, 'utf8') : Buffer.from(hashKey);
      if (key.length < 32) throw new ScreenError('invalid_hash_key');
      this.hashKey = key;
    }
    this.maxBytes = maxBytes;
  }

  /**
   * screen_text: the entry point. Steps in order: invalid_text 400; invalid_mode 400; invalid_categories 400;
   * text_too_large 413 (all before any scan); scan; reject with findings 422; redact; strip re-scan 422 when a match
   * only appears once its neighbour is redacted; the hidden escape check 422 in both modes; else 200. Anything
   * raised while scanning is 500 screening_failed (fail closed).
   * In: text, mode ("reject" | "strip"), categories (non-empty, "secret" and "pii" only). Out: ScreenOk or
   * ScreenRefusal (a refusal never carries the text). Why: spec screen_text (SCREEN-01..14). 2026-11-10,
   * session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  screenText(text: unknown, mode: unknown = 'reject', categories: unknown = ['secret', 'pii']): ScreenOk | ScreenRefusal {
    if (typeof text !== 'string' || !(text as any).isWellFormed()) return { ok: false, error: 'invalid_text', status: 400 };
    if (mode !== 'reject' && mode !== 'strip') return { ok: false, error: 'invalid_mode', status: 400 };
    if (!Array.isArray(categories) || categories.length === 0 || categories.some((c) => c !== 'secret' && c !== 'pii')) {
      return { ok: false, error: 'invalid_categories', status: 400 };
    }
    if (Buffer.byteLength(text, 'utf8') > this.maxBytes) return { ok: false, error: 'text_too_large', status: 413 };
    const cats = categories as string[];
    try {
      const f = this.scanText(text, cats);
      if (mode === 'reject' && f.length) return { ok: false, error: 'secrets_or_pii_detected', status: 422, findings: f };
      const out = f.length ? this.redactText(text, f) : text;
      if (mode === 'strip' && f.length) {
        const f2 = this.scanText(out, cats);
        if (f2.length) {
          return { ok: false, error: 'secrets_or_pii_detected', status: 422,
            findings: [...f, ...f2.map((x) => ({ ...x, start: -1, end: -1 }))] };
        }
      }
      if (out.includes('\\')) {
        const r = resolveEscapes(out);
        const hidden: Finding[] = r.text !== out
          ? this.scanText(r.text, cats).map((x) => ({ ...x, start: -1, end: -1, encoded: true })) : [];
        if (r.unresolved) {
          hidden.push({ category: 'secret', label: 'unresolved_escape', start: -1, end: -1, preview: '***', value_hash: null, encoded: true });
        }
        if (hidden.length) return { ok: false, error: 'secrets_or_pii_detected', status: 422, findings: [...f, ...hidden] };
      }
      return { ok: true, status: 200, text: out, findings: f };
    } catch {
      return { ok: false, error: 'screening_failed', status: 500 };
    }
  }

  /**
   * scan_text: every detector of the asked categories, then COMBINING (earliest start, then the longest span, then
   * the lower detector number; no character in two findings). In: text, categories. Out: findings ordered by start,
   * positions in code points. Why: spec scan_text and MATCHING. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
   * Touches nothing.
   */
  scanText(text: string, categories: string[] = ['secret', 'pii']): Finding[] {
    const wantSecret = categories.includes('secret');
    const wantPii = categories.includes('pii');
    const lower = asciiLower(text);
    const tables = new TextTables(text, lower);
    let cands: Candidate[] = [];
    if (wantSecret) cands.push(...pemCutOff(text), ...jwt(text));
    for (const d of DETECTORS) {
      if ((d.category === 'secret' && wantSecret) || (d.category === 'pii' && wantPii)) cands.push(...findAll(d, text, lower, tables));
    }
    const at = (u: number) => tables.cpCount(0, u);
    cands = cands.sort((a, b) => at(a.start) - at(b.start) || (at(b.end) - at(b.start)) - (at(a.end) - at(a.start)) || a.detector - b.detector);
    const findings: Finding[] = [];
    let lastEnd = -1;
    for (const c of cands) {
      if (c.start < lastEnd) continue;
      lastEnd = c.end;
      const value = text.slice(c.start, c.end);
      findings.push({
        category: c.category, label: c.label, start: at(c.start), end: at(c.end), preview: mask(value),
        value_hash: this.hashKey ? createHmac('sha256', this.hashKey).update(value, 'utf8').digest('hex') : null,
        encoded: false,
      });
    }
    return findings;
  }

  /**
   * redact_text: each finding's span (code points) replaced by "[REDACTED:" + label + "]", built in ONE left-to-right
   * pass. Findings without a position (start -1) are skipped. In: text, findings. Out: the redacted text.
   * Why: spec redact_text (SCREEN-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
   */
  redactText(text: string, findings: Finding[]): string {
    const spans = findings.filter((f) => f.start >= 0 && f.end >= f.start).sort((a, b) => a.start - b.start);
    const parts: string[] = [];
    let u = 0;
    let c = 0;
    const advanceTo = (target: number) => {
      const from = u;
      while (c < target && u < text.length) {
        const x = text.charCodeAt(u);
        u += x >= 0xd800 && x <= 0xdbff && u + 1 < text.length && text.charCodeAt(u + 1) >= 0xdc00 && text.charCodeAt(u + 1) <= 0xdfff ? 2 : 1;
        c++;
      }
      return text.slice(from, u);
    };
    for (const f of spans) {
      if (f.start < c) continue;
      parts.push(advanceTo(f.start));
      advanceTo(f.end);
      parts.push('[REDACTED:' + f.label + ']');
    }
    parts.push(text.slice(u));
    return parts.join('');
  }
}

/**
 * new_screener(hash_key = none, max_bytes = 1048576). In: hash key, max bytes. Out: a Screener. Throws
 * ScreenError("invalid_hash_key"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
 */
export function newScreener(hashKey?: Uint8Array | string | null, maxBytes = 1048576): Screener {
  return new Screener(hashKey, maxBytes);
}
