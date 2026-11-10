//! Secret & PII screening: find secrets and personal data in a text before it is stored, logged or shared,
//! and either refuse the text (mode "reject") or replace each match with a [REDACTED:label] marker ("strip").
//!
//! What: `Screener::screen_text` runs the 19 detectors of docs/specs/secret_pii_screening.md, combines their
//! candidates (earliest start, then longest span, then detector number), and answers with a returned value,
//! never a panic: a detector that panics is caught and answered 500 screening_failed (fail closed).
//! Positions are Unicode code points. The regexes run anchored at each candidate position (`^(?:...)` on a
//! slice), which gives exactly the spec's "leftmost match at or after pos" procedure, and positions whose
//! "before" guard fails are skipped without running the regex, so hostile inputs stay fast.
//! Why: Phase D wave 1, owner request 2026-11-10 (spec SCREEN-01..14).
//! 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
//! Touches: memory only. No database, file, network or money. Never logs a text, a match or the hash key.

use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha256;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Default largest text, in UTF-8 bytes (spec: new_screener max_bytes = 1048576).
pub const DEFAULT_MAX_BYTES: usize = 1_048_576;

/// What: one finding. start/end are code points (end exclusive), or -1 for a finding with no position
/// (encoded, or found only after redaction). preview = mask(matched text); value_hash = HMAC-SHA256 hex or None.
/// Why: spec scan_text "finding". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub category: String,
    pub label: String,
    pub start: i64,
    pub end: i64,
    pub preview: String,
    pub value_hash: Option<String>,
    pub encoded: bool,
}

/// What: methods of `Finding`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl Finding {
    /// What: the finding as JSON, with the spec's field names. In: self. Out: a serde_json value.
    /// Why: SCREEN-09 (a caller may store findings as they are). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: nothing.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "category": self.category, "label": self.label, "start": self.start, "end": self.end,
            "preview": self.preview, "value_hash": self.value_hash, "encoded": self.encoded,
        })
    }
}

/// What: the answer of screen_text. A refusal has ok false, its error and status, and never `text`.
/// Why: spec CONVENTIONS (a refusal is a returned value). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenResult {
    pub ok: bool,
    pub status: u16,
    pub error: Option<String>,
    pub text: Option<String>,
    pub findings: Vec<Finding>,
}

/// What: methods of `ScreenResult`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
impl ScreenResult {
    /// What: a refusal with no findings. In: error code, HTTP status. Out: the result.
    /// Why: steps 1-4 and fail-closed. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn refuse(error: &str, status: u16, findings: Vec<Finding>) -> ScreenResult {
        ScreenResult { ok: false, status, error: Some(error.to_string()), text: None, findings }
    }

    /// What: the result as JSON: {ok, status, error?, text?, findings}. A refusal has no "text" key.
    /// Why: SCREEN-09 (the serialized refusal holds neither the text nor a matched value).
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "ok": self.ok, "status": self.status,
            "findings": self.findings.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        });
        if let Some(e) = &self.error {
            v["error"] = serde_json::json!(e);
        }
        if let Some(t) = &self.text {
            v["text"] = serde_json::json!(t);
        }
        v
    }
}

/// What: the answer of resolve_escapes: the resolved text, and whether an ESCAPE is still left after 8 passes.
/// Why: spec ESCAPES. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub text: String,
    pub unresolved: bool,
}

/// A candidate before combining: byte span, detector number, label, category.
#[derive(Debug, Clone)]
struct Cand {
    start: usize,
    end: usize,
    det: usize,
    label: &'static str,
    secret: bool,
}

/// What: the screener: the compiled detectors, the optional hash key and the size limit.
/// Why: spec new_screener. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
pub struct Screener {
    hash_key: Option<Vec<u8>>,
    max_bytes: usize,
    re_pem: Regex,
    re_pem_header: Regex,
    re_openai: Regex,
    re_stripe: Regex,
    re_aws: Regex,
    re_github: Regex,
    re_slack: Regex,
    re_google: Regex,
    re_whsec: Regex,
    re_bearer: Regex,
    re_url: Regex,
    re_kv: Regex,
    re_email: Regex,
    re_phone: Regex,
    re_card: Regex,
    re_ssn: Regex,
    re_ipv4: Regex,
    re_ipv6: Regex,
    re_card_prefix: Regex,
}

const PLACEHOLDERS: &[&str] = &[
    "changeme", "change_me", "your_key_here", "your-key-here", "xxx", "xxxx", "xxxxx", "redacted", "todo", "example",
    "placeholder", "secret", "password", "insert_key_here", "none", "null", "n/a", "na", "<your-password>",
    "<your-key>", "fillmein",
];

/// What: compile a core regex anchored at the start of the slice it runs on. In: the spec's regex text.
/// Out: the compiled regex. Why: MATCHING (anchored search at each position = leftmost match procedure).
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn anchored(pattern: &str) -> Regex {
    Regex::new(&format!("^(?:{})", pattern)).expect("core regex compiles")
}

/// What: true for a byte of W = [A-Za-z0-9_]. Continuation bytes of a multi-byte character are never W.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn is_w(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// What: the ASCII lower case of a text: A-Z to a-z, every other character unchanged (positions stay).
/// Why: CONVENTIONS ("never the language's own lower-case function"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
pub fn ascii_lower(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_uppercase() { c.to_ascii_lowercase() } else { c }).collect()
}

/// What: mask(value): under 16 code points all "*", else 2 + "*" * (n - 4) + 2. In: value. Out: the preview.
/// Why: spec mask, SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    if n < 16 {
        return "*".repeat(n);
    }
    let mut out = String::new();
    out.extend(&chars[..2]);
    out.push_str(&"*".repeat(n - 4));
    out.extend(&chars[n - 2..]);
    out
}

/// What: looks_like_secret(v): a digit 0-9; or a char below U+0080 outside [A-Za-z0-9]; or 2 places a-z then A-Z.
/// Why: spec detector 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn looks_like_secret(v: &str) -> bool {
    if v.chars().any(|c| c.is_ascii_digit() || ((c as u32) < 0x80 && !c.is_ascii_alphanumeric())) {
        return true;
    }
    lower_upper_pairs(v) >= 2
}

/// What: how many places a letter a-z is directly followed by a letter A-Z. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn lower_upper_pairs(v: &str) -> usize {
    let b = v.as_bytes();
    (1..b.len()).filter(|&i| b[i - 1].is_ascii_lowercase() && b[i].is_ascii_uppercase()).count()
}

/// What: true when s is a NAME: a letter or "_", then letters, digits 0-9 and "_".
/// Why: spec REFERENCE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn is_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b[1..].iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')
}

/// What: true when every part of s split at "." is a NAME. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn dotted_names(s: &str) -> bool {
    s.split('.').all(is_name)
}

/// What: REFERENCE(V) for V = text[vs..vs + len]: a variable, template or mask; a call or index on a dotted
/// name; or a digit-free dotted name. With the first "(" or "[" taken from a table so a long value
/// is not searched once per match; the same answer as `is_reference`, the dotted-name test short-circuits.
/// Why: spec detector 13 and the 2026-11-10 ruling (fed6e7b): linear time on "token=$" * 28571.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn is_reference_at(text: &str, vs: usize, len: usize, next_paren: &[usize]) -> bool {
    let v = &text[vs..vs + len];
    if matches!(v.as_bytes().first(), Some(b'$' | b'<' | b'{' | b'%' | b'*')) {
        return true;
    }
    let pi = next_paren[vs];
    if pi < vs + len && dotted_names(&text[vs..pi]) {
        return true;
    }
    dotted_names(v) && v.contains('.') && !v.bytes().any(|b| b.is_ascii_digit())
}

/// What: the Luhn check over ASCII digits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = (d - b'0') as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum % 10 == 0
}

/// What: true when the text at byte i is an ESCAPE (\uXXXX or a backslash then one of " \ / b f n r t).
/// Why: spec ESCAPES. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn escape_at(b: &[u8], i: usize) -> bool {
    if b[i] != b'\\' || i + 1 >= b.len() {
        return false;
    }
    match b[i + 1] {
        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => true,
        b'u' => hex4(b, i + 2).is_some(),
        _ => false,
    }
}

/// What: the 4 hex digits at byte i as a number, if all four are hex. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn hex4(b: &[u8], i: usize) -> Option<u32> {
    if i + 4 > b.len() {
        return None;
    }
    let s = std::str::from_utf8(&b[i..i + 4]).ok()?;
    if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// What: true when the text holds an ESCAPE anywhere. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn holds_escape(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len()).any(|i| escape_at(b, i))
}

/// What: one left-to-right pass that replaces every ESCAPE (surrogate pairs joined, lone surrogates U+FFFD).
/// Why: spec ESCAPES. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn escape_pass(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && escape_at(b, i) {
            let c = b[i + 1];
            if c == b'u' {
                let u = hex4(b, i + 2).unwrap_or(0xFFFD);
                if (0xD800..=0xDBFF).contains(&u) && i + 12 <= b.len() && b[i + 6] == b'\\' && b[i + 7] == b'u' {
                    if let Some(lo) = hex4(b, i + 8) {
                        if (0xDC00..=0xDFFF).contains(&lo) {
                            let cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            i += 12;
                            continue;
                        }
                    }
                }
                out.push(char::from_u32(u).unwrap_or('\u{FFFD}'));
                i += 6;
            } else {
                out.push(match c {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{8}',
                    b'f' => '\u{c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    _ => '\t',
                });
                i += 2;
            }
        } else {
            let ch = s[i..].chars().next().expect("char boundary");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// What: resolve_escapes(text): repeat the escape pass while the text holds an ESCAPE, at most 8 times.
/// In: text. Out: {text, unresolved}. Why: spec step 9 (hidden check), SCREEN-13.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn resolve_escapes(text: &str) -> Resolved {
    let mut t = text.to_string();
    for _ in 0..8 {
        if !holds_escape(&t) {
            return Resolved { text: t, unresolved: false };
        }
        t = escape_pass(&t);
    }
    let unresolved = holds_escape(&t);
    Resolved { text: t, unresolved }
}

/// What: redact_text(text, findings): each finding's span replaced by "[REDACTED:" + label + "]", in ONE
/// left-to-right pass. Findings with no position (start -1) are skipped. In: text, findings ordered by start.
/// Out: the new text. Why: spec redact_text, SCREEN-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
pub fn redact_text(text: &str, findings: &[Finding]) -> String {
    let spans: Vec<&Finding> = findings.iter().filter(|f| f.start >= 0).collect();
    let mut out = String::with_capacity(text.len());
    let mut k = 0;
    for (i, ch) in text.chars().enumerate() {
        let i = i as i64;
        while k < spans.len() && spans[k].end <= i {
            k += 1;
        }
        if k < spans.len() && i >= spans[k].start {
            if i == spans[k].start {
                out.push_str("[REDACTED:");
                out.push_str(&spans[k].label);
                out.push(']');
            }
            continue;
        }
        out.push(ch);
    }
    out
}

/// What: methods of `Screener`. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
impl Screener {
    /// What: new_screener(hash_key, max_bytes). In: optional hash key (at least 32 bytes), max_bytes.
    /// Out: the screener, or Err("invalid_hash_key") for a key under 32 bytes (fail closed).
    /// Why: spec new_screener, SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    pub fn new(hash_key: Option<&[u8]>, max_bytes: usize) -> Result<Screener, String> {
        if let Some(k) = hash_key {
            if k.len() < 32 {
                return Err("invalid_hash_key".to_string());
            }
        }
        let header = r"-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----";
        Ok(Screener {
            hash_key: hash_key.map(|k| k.to_vec()),
            max_bytes,
            re_pem: anchored(&format!(
                r"{}(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{{1,32}},[0-9A-Fa-f]{{1,64}}\r?\n)?[^-]*-----END (?:[A-Z0-9]+ ){{0,8}}PRIVATE KEY(?: BLOCK)?-----",
                header
            )),
            re_pem_header: anchored(header),
            re_openai: anchored(r"sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]"),
            re_stripe: anchored(r"[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}"),
            re_aws: anchored(r"A[KS]IA[0-9A-Z]{16}"),
            re_github: anchored(r"gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}"),
            re_slack: anchored(r"xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]"),
            re_google: anchored(r"AIza[0-9A-Za-z_-]{35}"),
            re_whsec: anchored(r"whsec_[A-Za-z0-9+/=]{16,500}"),
            re_bearer: anchored(r"[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})"),
            re_url: anchored(r"[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@"),
            re_kv: anchored(
                r#"(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key|credentials?|token)(?:\\?["'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?["'])?"#,
            ),
            re_email: anchored(r"[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}"),
            re_phone: anchored(r"(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}"),
            re_card: anchored(r"[0-9](?:[ -]?[0-9]){12,18}"),
            re_ssn: anchored(r"[0-9]{3}-[0-9]{2}-[0-9]{4}"),
            re_ipv4: anchored(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"),
            re_ipv6: anchored(r"[0-9A-Fa-f:]{2,39}"),
            re_card_prefix: anchored(
                r"4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])|3(?:0[0-5]|[68][0-9])|35[0-9][0-9]",
            ),
        })
    }

    /// What: screen_text(text, mode, categories): the entry point, steps 2-10 of the spec in order (step 1,
    /// "not well-formed text", cannot happen for a Rust &str). In: text, mode, categories. Out: the result,
    /// never a panic. Why: spec screen_text, SCREEN-01..14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory only.
    pub fn screen_text(&self, text: &str, mode: &str, categories: &[&str]) -> ScreenResult {
        if mode != "reject" && mode != "strip" {
            return ScreenResult::refuse("invalid_mode", 400, vec![]);
        }
        if categories.is_empty() || categories.iter().any(|c| *c != "secret" && *c != "pii") {
            return ScreenResult::refuse("invalid_categories", 400, vec![]);
        }
        if text.len() > self.max_bytes {
            return ScreenResult::refuse("text_too_large", 413, vec![]);
        }
        match catch_unwind(AssertUnwindSafe(|| self.screen_checked(text, mode, categories))) {
            Ok(r) => r,
            Err(_) => ScreenResult::refuse("screening_failed", 500, vec![]),
        }
    }

    /// What: steps 5-10 of screen_text, after the input checks. Why: spec steps 5-10.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn screen_checked(&self, text: &str, mode: &str, categories: &[&str]) -> ScreenResult {
        let f = self.scan_text(text, categories);
        if mode == "reject" && !f.is_empty() {
            return ScreenResult::refuse("secrets_or_pii_detected", 422, f);
        }
        let out = if f.is_empty() { text.to_string() } else { redact_text(text, &f) };
        if mode == "strip" && !f.is_empty() {
            let f2 = self.scan_text(&out, categories);
            if !f2.is_empty() {
                let mut all = f.clone();
                all.extend(f2.into_iter().map(|mut x| {
                    x.start = -1;
                    x.end = -1;
                    x
                }));
                return ScreenResult::refuse("secrets_or_pii_detected", 422, all);
            }
        }
        if out.contains('\\') {
            let r = resolve_escapes(&out);
            let mut h: Vec<Finding> = Vec::new();
            if r.text != out {
                h.extend(self.scan_text(&r.text, categories).into_iter().map(|mut x| {
                    x.encoded = true;
                    x.start = -1;
                    x.end = -1;
                    x
                }));
            }
            if r.unresolved {
                h.push(Finding {
                    category: "secret".into(),
                    label: "unresolved_escape".into(),
                    start: -1,
                    end: -1,
                    preview: "***".into(),
                    value_hash: None,
                    encoded: true,
                });
            }
            if !h.is_empty() {
                let mut all = f;
                all.extend(h);
                return ScreenResult::refuse("secrets_or_pii_detected", 422, all);
            }
        }
        ScreenResult { ok: true, status: 200, error: None, text: Some(out), findings: f }
    }

    /// What: value_hash = lower-case hex of HMAC-SHA256(hash_key, value), or None without a key.
    /// Why: spec scan_text, SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
    fn value_hash(&self, value: &str) -> Option<String> {
        let key = self.hash_key.as_ref()?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
        mac.update(value.as_bytes());
        Some(mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect())
    }

    /// What: scan_text(text, categories): every candidate of the detectors whose category is asked for,
    /// combined so no character is in two findings, ordered by start; positions in code points.
    /// Why: spec scan_text and COMBINING, SCREEN-02..08, SCREEN-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory only.
    pub fn scan_text(&self, text: &str, categories: &[&str]) -> Vec<Finding> {
        let want_secret = categories.contains(&"secret");
        let want_pii = categories.contains(&"pii");
        let mut c: Vec<Cand> = Vec::new();
        if want_secret {
            self.secret_candidates(text, &mut c);
        }
        if want_pii {
            self.pii_candidates(text, &mut c);
        }
        c.sort_by(|a, b| a.start.cmp(&b.start).then((b.end - b.start).cmp(&(a.end - a.start))).then(a.det.cmp(&b.det)));
        let mut kept: Vec<Cand> = Vec::new();
        let mut last_end = 0usize;
        for x in c {
            if kept.is_empty() || x.start >= last_end {
                last_end = x.end;
                kept.push(x);
            }
        }
        // byte offset -> code point index, one pass
        let mut cp = vec![0i64; text.len() + 1];
        let mut n = 0i64;
        for (i, ch) in text.char_indices() {
            for j in 0..ch.len_utf8() {
                cp[i + j] = n;
            }
            n += 1;
        }
        cp[text.len()] = n;
        kept.into_iter()
            .map(|x| {
                let value = &text[x.start..x.end];
                Finding {
                    category: if x.secret { "secret" } else { "pii" }.to_string(),
                    label: x.label.to_string(),
                    start: cp[x.start],
                    end: cp[x.end],
                    preview: mask(value),
                    value_hash: self.value_hash(value),
                    encoded: false,
                }
            })
            .collect()
    }

    /// What: the candidates of detectors 1-13 (secrets). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn secret_candidates(&self, text: &str, c: &mut Vec<Cand>) {
        let b = text.as_bytes();
        let n = b.len();
        let after_not_w = |e: usize| e < n && !is_w(b[e]);
        let starts = |p: usize, s: &str| b[p..].starts_with(s.as_bytes());
        // 1 pem_private_key (complete block)
        scan(text, &self.re_pem, |p| starts(p, "-----BEGIN "), |_, s, e| Some((s, e)), 1, "pem_private_key", true, c);
        // 2 pem_private_key (cut off before its END line), by hand
        self.pem_truncated(text, c);
        // 3 openai_style_api_key
        scan(text, &self.re_openai, |p| starts(p, "sk-") && before_not_w_or_none(b, p),
            |_, s, e| if b[s..e].iter().any(|x| x.is_ascii_digit()) { Some((s, e)) } else { None },
            3, "openai_style_api_key", true, c);
        // 4 stripe_style_api_key
        scan(text, &self.re_stripe, |p| matches!(b[p], b's' | b'p' | b'r') && before_not_w_or_none(b, p),
            |_, s, e| if e == n || after_not_w(e) { Some((s, e)) } else { None }, 4, "stripe_style_api_key", true, c);
        // 5 aws_access_key_id
        scan(text, &self.re_aws, |p| b[p] == b'A' && before_not_w_or_none(b, p),
            |_, s, e| if e == n || after_not_w(e) { Some((s, e)) } else { None }, 5, "aws_access_key_id", true, c);
        // 6 github_token
        scan(text, &self.re_github, |p| b[p] == b'g' && before_not_w_or_none(b, p),
            |_, s, e| if e == n || after_not_w(e) { Some((s, e)) } else { None }, 6, "github_token", true, c);
        // 7 slack_token
        scan(text, &self.re_slack, |p| starts(p, "xox") && before_not_w_or_none(b, p),
            |_, s, e| if e == n || after_not_w(e) { Some((s, e)) } else { None }, 7, "slack_token", true, c);
        // 8 google_api_key
        scan(text, &self.re_google, |p| starts(p, "AIza") && before_not_w_or_none(b, p),
            |_, s, e| if e == n || (after_not_w(e) && b[e] != b'-') { Some((s, e)) } else { None }, 8, "google_api_key", true, c);
        // 9 webhook_signing_secret
        scan(text, &self.re_whsec, |p| starts(p, "whsec_") && before_not_w_or_none(b, p), |_, s, e| Some((s, e)),
            9, "webhook_signing_secret", true, c);
        // 10 jwt, by hand
        jwt(text, c);
        // 11 bearer_token: span group 1
        scan_groups(text, &self.re_bearer, |p| matches!(b[p], b'B' | b'b') && before_not_w_or_none(b, p),
            |g1s, g1e| {
                let g = &b[g1s..g1e];
                g.iter().any(|x| x.is_ascii_digit()) || lower_upper_pairs(&text[g1s..g1e]) >= 2
            },
            11, "bearer_token", c);
        // 12 url_credentials: span group 1
        let css = next_index(b, |i| b[i..].starts_with(b"://"));
        scan_groups(text, &self.re_url, |p| b[p].is_ascii_alphabetic() && p + 1 < n && css[p + 1] <= p + 31,
            |g1s, g1e| {
                let g = &text[g1s..g1e];
                !g.starts_with("[REDACTED:") && !PLACEHOLDERS.contains(&ascii_lower(g).as_str())
            },
            12, "url_credentials", c);
        // 13 generic_key_value_assignment, matched on LOWER
        self.key_value(text, c);
    }

    /// What: detector 2, a private key block cut off before its END line (a procedure, not a regex).
    /// Why: spec detector 2, SCREEN-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn pem_truncated(&self, text: &str, c: &mut Vec<Cand>) {
        let b = text.as_bytes();
        let n = b.len();
        let mut pos = 0usize;
        while pos < n {
            // h = the leftmost header match at or after pos
            let mut h: Option<(usize, usize)> = None;
            let mut p = pos;
            while p < n {
                if text.is_char_boundary(p) && b[p..].starts_with(b"-----BEGIN ") {
                    if let Some(m) = self.re_pem_header.find(&text[p..]) {
                        h = Some((p, p + m.end()));
                        break;
                    }
                }
                p += 1;
            }
            let (hs, he) = match h {
                Some(x) => x,
                None => return,
            };
            let mut p = he;
            let mut count = 0usize;
            let mut end: Option<usize> = None;
            loop {
                let mut q = p;
                loop {
                    if q < n && matches!(b[q], b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'-') {
                        q += 1;
                    } else if b[q..].starts_with(b"\\r\\n") {
                        q += 4;
                    } else if b[q..].starts_with(b"\\n") {
                        q += 2;
                    } else {
                        break;
                    }
                }
                let mut r = q;
                while r < n && (b[r].is_ascii_alphanumeric() || matches!(b[r], b'+' | b'/' | b'=')) {
                    r += 1;
                }
                if r - q < 16 {
                    break;
                }
                count += r - q;
                end = Some(r);
                p = r;
            }
            if count >= 60 {
                let e = end.expect("set with count");
                c.push(Cand { start: hs, end: e, det: 2, label: "pem_private_key", secret: true });
                pos = e;
            } else {
                pos = hs + 1;
            }
        }
    }

    /// What: detector 13, key = value assignments, matched on the ASCII lower case of the text.
    /// Why: spec detector 13, SCREEN-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn key_value(&self, text: &str, c: &mut Vec<Cand>) {
        let lower = ascii_lower(text);
        let lb = lower.as_bytes();
        let b = text.as_bytes();
        let n = b.len();
        // run[p] = length of the run of [a-z0-9_.-] just before p in LOWER
        let mut run = vec![0usize; n + 1];
        for i in 0..n {
            let x = lb[i];
            run[i + 1] = if x.is_ascii_lowercase() || x.is_ascii_digit() || matches!(x, b'_' | b'.' | b'-') { run[i] + 1 } else { 0 };
        }
        // value_end[i] = where a value starting at i ends (Phase D ruling fed6e7b: computed once, so a text
        // such as "token=$" * 28571 is linear); next_paren[i] = the first "(" or "[" at or after i
        let stop = |x: u8| matches!(x, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b | b'\'' | b'"');
        let mut value_end = vec![n; n + 1];
        for i in (0..n).rev() {
            let x = b[i];
            let ends = stop(x) || x == b';' || (x == b'\\' && i + 1 < n && stop(b[i + 1]));
            value_end[i] = if ends { i } else { value_end[i + 1] };
        }
        let next_paren = next_index(b, |i| b[i] == b'(' || b[i] == b'[');
        const WORDS: &[&str] = &["api", "secret", "password", "passwd", "pwd", "access", "auth", "private", "credential", "token"];
        let mut p = 0usize;
        while p < n {
            if !lower.is_char_boundary(p) || run[p] > 40 || !WORDS.iter().any(|w| lb[p..].starts_with(w.as_bytes())) {
                p += 1;
                continue;
            }
            let m_end = match self.re_kv.find(&lower[p..]) {
                Some(m) => p + m.end(),
                None => {
                    p += 1;
                    continue;
                }
            };
            // the value, from the ORIGINAL text; its end comes from the table, and the checks that refuse at
            // once (a marker, a short value, a variable or template, a placeholder) run before any that read it all
            let vs = m_end;
            let mut accepted = None;
            if !b[vs..].starts_with(b"[REDACTED:") {
                let ve = value_end[vs];
                let value = &text[vs..ve];
                if value.chars().take(8).count() >= 8 {
                    let v = value.trim_end_matches(|ch| matches!(ch, '.' | ',' | ';' | ':' | '!' | '?'));
                    let instant_no = matches!(v.as_bytes().first(), Some(b'$' | b'<' | b'{' | b'%' | b'*'))
                        || (v.len() <= 16 && PLACEHOLDERS.contains(&ascii_lower(v).as_str()));
                    if !instant_no && !is_reference_at(text, vs, v.len(), &next_paren) && looks_like_secret(v) {
                        accepted = Some(ve);
                    }
                }
            }
            match accepted {
                Some(ve) => {
                    c.push(Cand { start: vs, end: ve, det: 13, label: "generic_key_value_assignment", secret: true });
                    p = ve;
                }
                None => p += 1,
            }
        }
    }

    /// What: the candidates of detectors 14-19 (personal data). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// Touches: memory only.
    fn pii_candidates(&self, text: &str, c: &mut Vec<Cand>) {
        let b = text.as_bytes();
        let n = b.len();
        let none_or = |e: usize, f: &dyn Fn(u8) -> bool| e >= n || f(b[e]);
        let before_ok = |p: usize, f: &dyn Fn(u8) -> bool| p == 0 || f(b[p - 1]);
        // 14 email_address (the '@' must lie within 64 bytes: the local part is 1-64 ASCII characters)
        let next_at = next_index(b, |i| b[i] == b'@');
        scan(text, &self.re_email,
            |p| (b[p].is_ascii_alphanumeric() || matches!(b[p], b'.' | b'_' | b'%' | b'+' | b'-'))
                && before_ok(p, &|x| !is_w(x))
                && next_at[p] <= p + 64,
            |_, s, e| {
                if !none_or(e, &|x| !is_w(x)) {
                    return None;
                }
                // not the user part of a URL
                let mut k = s;
                while k > 0 {
                    k -= 1;
                    if matches!(b[k], b'/' | b'@' | b' ' | b'\t' | b'\r' | b'\n') {
                        if k >= 2 && &b[k - 2..=k] == b"://" {
                            return None;
                        }
                        break;
                    }
                }
                Some((s, e))
            },
            14, "email_address", false, c);
        // 15 phone_number
        scan(text, &self.re_phone, |p| (b[p].is_ascii_digit() || matches!(b[p], b'+' | b'(')) && before_ok(p, &|x| !x.is_ascii_digit()),
            |_, s, e| if e >= n || !b[e].is_ascii_digit() { Some((s, e)) } else { None }, 15, "phone_number", false, c);
        // 16 credit_card_number
        self.cards(text, c);
        // 17 ssn
        scan(text, &self.re_ssn, |p| b[p].is_ascii_digit() && before_ok(p, &|x| !is_w(x) && x != b'-'),
            |_, s, e| {
                if e < n && (is_w(b[e]) || b[e] == b'-') {
                    return None;
                }
                let t = &text[s..e];
                let (a, g, l) = (&t[0..3], &t[4..6], &t[7..11]);
                if a == "000" || a == "666" || a.starts_with('9') || g == "00" || l == "0000" {
                    return None;
                }
                Some((s, e))
            },
            17, "ssn", false, c);
        // 18 ip_address, IPv4
        scan(text, &self.re_ipv4, |p| b[p].is_ascii_digit() && before_ok(p, &|x| !is_w(x) && x != b'.'),
            |_, s, e| {
                if e < n && is_w(b[e]) {
                    return None;
                }
                if e < n && b[e] == b'.' && e + 1 < n && b[e + 1].is_ascii_digit() {
                    return None;
                }
                let parts: Vec<&str> = text[s..e].split('.').collect();
                let mut nums = [0u32; 4];
                for (i, part) in parts.iter().enumerate() {
                    if part.len() > 1 && part.starts_with('0') {
                        return None;
                    }
                    nums[i] = part.parse().ok()?;
                    if nums[i] > 255 {
                        return None;
                    }
                }
                let (a, bb) = (nums[0], nums[1]);
                if a == 0 || a == 10 || a == 127 || a >= 224 {
                    return None;
                }
                if (a == 169 && bb == 254) || (a == 172 && (16..=31).contains(&bb)) || (a == 192 && bb == 168) || nums[3] == 0 {
                    return None;
                }
                Some((s, e))
            },
            18, "ip_address", false, c);
        // 19 ip_address, IPv6
        scan(text, &self.re_ipv6,
            |p| (b[p].is_ascii_hexdigit() || b[p] == b':') && before_ok(p, &|x| !is_w(x) && x != b':' && x != b'.'),
            |_, s, e| {
                if e < n && (is_w(b[e]) || b[e] == b':') {
                    return None;
                }
                if ipv6_global(&text[s..e]) { Some((s, e)) } else { None }
            },
            19, "ip_address", false, c);
    }

    /// What: detector 16, card numbers: the longest prefix of the match that holds 13-19 digits, ends at a
    /// separator or at the end with after not W, is grouped like a card, has a card prefix and passes Luhn.
    /// Why: spec detector 16, SCREEN-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
    fn cards(&self, text: &str, c: &mut Vec<Cand>) {
        let b = text.as_bytes();
        let n = b.len();
        let mut p = 0usize;
        while p < n {
            if !b[p].is_ascii_digit() || (p > 0 && is_w(b[p - 1])) {
                p += 1;
                continue;
            }
            let e = match self.re_card.find(&text[p..]) {
                Some(m) => p + m.end(),
                None => {
                    p += 1;
                    continue;
                }
            };
            let digits: Vec<u8> = b[p..e].iter().copied().filter(|x| x.is_ascii_digit()).collect();
            let mut found = None;
            if self.re_card_prefix.is_match(std::str::from_utf8(&digits).expect("ascii")) {
                let mut ends: Vec<usize> = Vec::new();
                if e >= n || !is_w(b[e]) {
                    ends.push(e);
                }
                for k in (p + 1..e).rev() {
                    if b[k] == b' ' || b[k] == b'-' {
                        ends.push(k);
                    }
                }
                for end in ends {
                    let pre = &text[p..end];
                    let d: Vec<u8> = pre.bytes().filter(|x| x.is_ascii_digit()).collect();
                    if d.len() < 13 || d.len() > 19 {
                        continue;
                    }
                    let groups: Vec<&str> = pre.split(|ch| ch == ' ' || ch == '-').collect();
                    if groups[..groups.len() - 1].iter().any(|g| g.len() < 4) {
                        continue;
                    }
                    if luhn(&d) {
                        found = Some(end);
                        break;
                    }
                }
            }
            match found {
                Some(end) => {
                    c.push(Cand { start: p, end, det: 16, label: "credit_card_number", secret: false });
                    p = end;
                }
                None => p += 1,
            }
        }
    }
}

/// What: true when position p has no "before" character, or one that is not W.
/// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn before_not_w_or_none(b: &[u8], p: usize) -> bool {
    p == 0 || !is_w(b[p - 1])
}

/// What: next[i] = the smallest j >= i where pred(j) holds, or usize::MAX/2; one backward pass.
/// Why: quick, exact pre-checks that keep hostile inputs linear (MATCHING). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
/// Touches: nothing.
fn next_index(b: &[u8], pred: impl Fn(usize) -> bool) -> Vec<usize> {
    let far = usize::MAX / 2;
    let mut v = vec![far; b.len() + 1];
    for i in (0..b.len()).rev() {
        v[i] = if pred(i) { i } else { v[i + 1] };
    }
    v
}

/// What: find_all for a regex detector: at each char boundary p where `may_start(p)` holds (the first
/// character and the "before" guard, both exact), the anchored match at p is the leftmost match; when
/// `accept` gives a span it is a candidate and the scan goes on at the end of the match, else at p + 1.
/// Why: spec MATCHING find_all. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
#[allow(clippy::too_many_arguments)]
fn scan(
    text: &str,
    re: &Regex,
    may_start: impl Fn(usize) -> bool,
    accept: impl Fn(&str, usize, usize) -> Option<(usize, usize)>,
    det: usize,
    label: &'static str,
    secret: bool,
    c: &mut Vec<Cand>,
) {
    let n = text.len();
    let mut p = 0usize;
    while p < n {
        if !text.is_char_boundary(p) || !may_start(p) {
            p += 1;
            continue;
        }
        match re.find(&text[p..]) {
            Some(m) => {
                let (s, e) = (p, p + m.end());
                match accept(text, s, e) {
                    Some((cs, ce)) => {
                        c.push(Cand { start: cs, end: ce, det, label, secret });
                        p = e;
                    }
                    None => p += 1,
                }
            }
            None => p += 1,
        }
    }
}

/// What: find_all for a detector whose span is capture group 1; `check` sees the group's byte span.
/// Why: spec detectors 11 and 12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
fn scan_groups(
    text: &str,
    re: &Regex,
    may_start: impl Fn(usize) -> bool,
    check: impl Fn(usize, usize) -> bool,
    det: usize,
    label: &'static str,
    c: &mut Vec<Cand>,
) {
    let n = text.len();
    let mut p = 0usize;
    while p < n {
        if !text.is_char_boundary(p) || !may_start(p) {
            p += 1;
            continue;
        }
        match re.captures(&text[p..]) {
            Some(caps) => {
                let m = caps.get(0).expect("whole match");
                let g = caps.get(1).expect("group 1");
                let (gs, ge) = (p + g.start(), p + g.end());
                if check(gs, ge) {
                    c.push(Cand { start: gs, end: ge, det, label, secret: true });
                    p += m.end();
                } else {
                    p += 1;
                }
            }
            None => p += 1,
        }
    }
}

/// What: detector 10, JSON Web Tokens, by hand so it is linear: "eyJ" + a run of S, ".", >= 5 S, ".", >= 5 S.
/// Why: spec detector 10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
fn jwt(text: &str, c: &mut Vec<Cand>) {
    let b = text.as_bytes();
    let n = b.len();
    let is_s = |x: u8| x.is_ascii_alphanumeric() || x == b'_' || x == b'-';
    let run_end = |mut k: usize| {
        while k < n && is_s(b[k]) {
            k += 1;
        }
        k
    };
    let mut pos = 0usize;
    while pos < n {
        let i = match text[pos..].find("eyJ") {
            Some(off) => pos + off,
            None => return,
        };
        if i > 0 && is_w(b[i - 1]) {
            pos = i + 1;
            continue;
        }
        let j = run_end(i);
        pos = j;
        if j - i >= 8 && j < n && b[j] == b'.' {
            let k = run_end(j + 1);
            if k - (j + 1) >= 5 && k < n && b[k] == b'.' {
                let e = run_end(k + 1);
                if e - (k + 1) >= 5 {
                    c.push(Cand { start: i, end: e, det: 10, label: "jwt", secret: true });
                    pos = e;
                }
            }
        }
    }
}

/// What: the IPv6 check: "::" at most once and never ":::"; 8 groups, or at most 7 around "::"; each group
/// 1-4 hex digits; the first group (0 when the text starts with "::") within 0x2000-0x3fff (global only).
/// Why: spec detector 19, SCREEN-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
fn ipv6_global(s: &str) -> bool {
    if s.contains(":::") || s.matches("::").count() > 1 {
        return false;
    }
    let group_ok = |g: &str| !g.is_empty() && g.len() <= 4 && g.bytes().all(|x| x.is_ascii_hexdigit());
    let groups_of = |part: &str| -> Option<Vec<String>> {
        if part.is_empty() {
            return Some(vec![]);
        }
        let gs: Vec<String> = part.split(':').map(|x| x.to_string()).collect();
        if gs.iter().all(|g| group_ok(g)) { Some(gs) } else { None }
    };
    let first: u32;
    if let Some(i) = s.find("::") {
        let left = match groups_of(&s[..i]) {
            Some(g) => g,
            None => return false,
        };
        let right = match groups_of(&s[i + 2..]) {
            Some(g) => g,
            None => return false,
        };
        if left.len() + right.len() > 7 {
            return false;
        }
        first = match left.first() {
            Some(g) => u32::from_str_radix(g, 16).unwrap_or(0),
            None => 0,
        };
    } else {
        let gs: Vec<&str> = s.split(':').collect();
        if gs.len() != 8 || !gs.iter().all(|g| group_ok(g)) {
            return false;
        }
        first = u32::from_str_radix(gs[0], 16).unwrap_or(0);
    }
    (0x2000..=0x3fff).contains(&first)
}
