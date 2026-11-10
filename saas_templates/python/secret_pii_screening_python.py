"""Secret & PII screening (docs/specs/secret_pii_screening.md): find secrets and personal data in a text before it
is stored, logged or shared, and either refuse the text (reject) or replace each match with a marker (strip).

Why: Phase D wave 1, owner request 2026-11-10 (SCREEN-01 to SCREEN-14). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
Touches: nothing outside memory (no database, files, network or money). Never logs the text, a matched value or
the hash key.

Inputs and outputs: new_screener(hash_key, max_bytes) -> Screener; Screener.screen_text(text, mode, categories)
-> a dict {ok, status, ...}; Screener.scan_text(text, categories) -> [finding]; redact_text, mask and
resolve_escapes are pure helpers. A refusal is a RETURNED dict, never an exception.
"""
import hashlib
import hmac
import re
from typing import Callable, Iterator, List, Optional, Sequence, Tuple

DEFAULT_MAX_BYTES = 1048576
ALL_CATEGORIES = ("secret", "pii")

# --------------------------------------------------------------------------------------------- small helpers
_UPPER_TO_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


def ascii_lower(s: str) -> str:
    """Map A-Z to a-z and change no other character, so code-point positions stay the same.

    In: a str. Out: a str of the same length. Why: CONVENTIONS "ASCII lower case" (str.lower would fold U+212A
    and U+0130). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return s.translate(_UPPER_TO_LOWER)


def _is_w(c: Optional[str]) -> bool:
    """True when c is a character of W = [A-Za-z0-9_]; None (no character) is not.

    Why: MATCHING guards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return c is not None and (("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c == "_")


def _is_digit(c: Optional[str]) -> bool:
    """True when c is one of the ASCII digits 0-9 (never another script's digit).

    Why: SCREEN-05 "only 0-9 are digits". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return c is not None and "0" <= c <= "9"


def _char_at(text: str, i: int) -> Optional[str]:
    """The character at i, or None outside the text (the "none" of the guards).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return text[i] if 0 <= i < len(text) else None


def _has_digit(s: str) -> bool:
    """True when s holds a digit 0-9. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return _DIGIT_RE.search(s) is not None


def _lower_upper_pairs(s: str) -> int:
    """The number of places where a letter a-z is directly followed by a letter A-Z (up to 2 is enough).

    Why: looks_like_secret and the bearer check. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return len(_AZ_PAIR_RE.findall(s))


_DIGIT_RE = re.compile(r"[0-9]")
_AZ_PAIR_RE = re.compile(r"[a-z](?=[A-Z])")  # helper only (not a detector's core regex)
_ASCII_SYMBOL_RE = re.compile(r"[\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]")


def looks_like_secret(v: str) -> bool:
    """looks_like_secret(v) of the spec: a digit 0-9; or a character below U+0080 outside [A-Za-z0-9]; or at least
    2 places where a-z is directly followed by A-Z. Characters at or above U+0080 pass none of the tests.

    In: the value. Out: bool. Why: detector 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return _has_digit(v) or _ASCII_SYMBOL_RE.search(v) is not None or _lower_upper_pairs(v) >= 2


PLACEHOLDERS = frozenset([
    "changeme", "change_me", "your_key_here", "your-key-here", "xxx", "xxxx", "xxxxx", "redacted", "todo",
    "example", "placeholder", "secret", "password", "insert_key_here", "none", "null", "n/a", "na",
    "<your-password>", "<your-key>", "fillmein",
])


def _is_name(s: str) -> bool:
    """A NAME: a letter A-Z a-z or "_" followed by letters, digits 0-9 and "_". Written as a loop, not a regex.

    Why: REFERENCE(V). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not s:
        return False
    c = s[0]
    if not (("a" <= c <= "z") or ("A" <= c <= "Z") or c == "_"):
        return False
    for c in s[1:]:
        if not _is_w(c):
            return False
    return True


def is_reference(v: str) -> bool:
    """REFERENCE(V): V says where a secret comes from (a variable, template, mask, call, index or dotted name).

    In: V. Out: bool. Why: detector 13 (SCREEN-05). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if v and v[0] in "$<{%*":
        return True
    cut = -1
    for i, c in enumerate(v):
        if c == "(" or c == "[":
            cut = i
            break
    if cut >= 0 and all(_is_name(p) for p in v[:cut].split(".")):
        return True
    if "." in v and not _has_digit(v) and all(_is_name(p) for p in v.split(".")):
        return True
    return False


def mask(value: str) -> str:
    """mask(value): under 16 code points -> that many "*"; otherwise the first 2, "*" * (n - 4), the last 2.

    In: the matched text. Out: the preview. Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches nothing."""
    n = len(value)
    if n < 16:
        return "*" * n
    return value[:2] + "*" * (n - 4) + value[-2:]


def redact_text(text: str, findings: Sequence[dict]) -> str:
    """Replace each finding's span by "[REDACTED:" + label + "]", in ONE left-to-right pass.

    In: the text and findings ordered by start, not overlapping (findings with start -1 are skipped). Out: the
    new text. Why: screen_text step 7 (SCREEN-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    parts: List[str] = []
    pos = 0
    for f in findings:
        s, e = f["start"], f["end"]
        if s < 0:
            continue
        parts.append(text[pos:s])
        parts.append("[REDACTED:" + f["label"] + "]")
        pos = e
    parts.append(text[pos:])
    return "".join(parts)


# --------------------------------------------------------------------------------------------------- escapes
_ESCAPE_ANY = re.compile(r'\\(?:u[0-9A-Fa-f]{4}|["\\/bfnrt])')
_ESCAPE_PASS = re.compile(
    r'\\u([dD][89abAB][0-9A-Fa-f]{2})\\u([dD][c-fC-F][0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})|\\(["\\/bfnrt])')
_SIMPLE_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _escape_replacement(m: "re.Match") -> str:
    """The character one ESCAPE stands for: a surrogate pair is one character, a lone surrogate U+FFFD.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if m.group(1) is not None:
        hi, lo = int(m.group(1), 16), int(m.group(2), 16)
        return chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
    if m.group(3) is not None:
        v = int(m.group(3), 16)
        return "�" if 0xD800 <= v <= 0xDFFF else chr(v)
    return _SIMPLE_ESCAPES[m.group(4)]


def resolve_escapes(text: str) -> dict:
    """resolve_escapes(text) -> {text, unresolved}: repeat the one-pass ESCAPE replacement while the text holds an
    ESCAPE, at most 8 times; unresolved = an ESCAPE is still there after the 8th pass.

    Why: screen_text step 9, the hidden check (SCREEN-13). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    Touches nothing."""
    out = text
    for _ in range(8):
        if _ESCAPE_ANY.search(out) is None:
            break
        out = _ESCAPE_PASS.sub(_escape_replacement, out)
    return {"text": out, "unresolved": _ESCAPE_ANY.search(out) is not None}


# ------------------------------------------------------------------------------------------------- detectors
Candidate = Tuple[int, int, int]  # (start, end, next pos)


def _find_all(rx: "re.Pattern", text: str, accept: Callable[["re.Match"], Optional[Candidate]]) -> Iterator[Candidate]:
    """MATCHING find_all: from pos, the leftmost match; accepted -> a candidate and pos = its next pos, refused ->
    pos = the match's start + 1.

    In: the core regex, the text it runs on, accept(m) -> (start, end, next) or None. Out: candidates.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    pos = 0
    n = len(text)
    while pos <= n:
        m = rx.search(text, pos)
        if m is None:
            return
        c = accept(m)
        if c is not None:
            yield c
            pos = c[2]
        else:
            pos = m.start() + 1


def _guards(text: str, m: "re.Match", before_ok: Callable[[Optional[str]], bool],
            after_ok: Callable[[Optional[str]], bool]) -> bool:
    """Apply a detector's before and after guard to the whole match m.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return before_ok(_char_at(text, m.start() - 1)) and after_ok(_char_at(text, m.end()))


def _not_w(c: Optional[str]) -> bool:
    """The guard "is not W": none, or a character outside W. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return not _is_w(c)


def _any(_c: Optional[str]) -> bool:
    """A guard that accepts everything. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return True


_RX_PEM = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----"
    r"(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\r?\n)?"
    r"[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----")
_RX_PEM_HEADER = re.compile(r"-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----")
_RX_B64_RUN = re.compile(r"[A-Za-z0-9+/=]*")
_RX_OPENAI = re.compile(r"sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]")
_RX_STRIPE = re.compile(r"[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}")
_RX_AWS = re.compile(r"A[KS]IA[0-9A-Z]{16}")
_RX_GITHUB = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}")
_RX_SLACK = re.compile(r"xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]")
_RX_GOOGLE = re.compile(r"AIza[0-9A-Za-z_-]{35}")
_RX_WHSEC = re.compile(r"whsec_[A-Za-z0-9+/=]{16,500}")
_RX_S_RUN = re.compile(r"[A-Za-z0-9_-]*")
_RX_BEARER = re.compile(r"[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})")
_RX_URLCRED = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@")
_RX_GENERIC = re.compile(
    r"(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|"
    r"private[_-]?key|credentials?|token)(?:\\?[\"'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?[\"'])?")
_RX_GENERIC_STOP = re.compile(r"[ \t\n\r\f\v'\";\\]")
_RX_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}")
_RX_PHONE = re.compile(r"(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}")
_RX_CARD = re.compile(r"[0-9](?:[ -]?[0-9]){12,18}")
_RX_CARD_PREFIX = re.compile(
    r"(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])"
    r"|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])")
_RX_SSN = re.compile(r"[0-9]{3}-[0-9]{2}-[0-9]{4}")
_RX_IPV4 = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
_RX_IPV6 = re.compile(r"[0-9A-Fa-f:]{2,39}")
_BLOCK_SKIP = frozenset(" \t\r\n>-")
_NAME_RUN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_.-")
_WS_STOP_AFTER_BACKSLASH = frozenset(" \t\n\r\f\v'\"")


def _det_pem(text: str) -> Iterator[Candidate]:
    """Detector 1, a whole private key block (its encrypted header included).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return _find_all(_RX_PEM, text, lambda m: (m.start(), m.end(), m.end()))


def _det_pem_cut(text: str) -> Iterator[Candidate]:
    """Detector 2, a block cut off before its END line, found by hand (no repeated group, see the spec): after a
    header, runs of 16+ key characters separated by space, tab, CR, LF, ">", "-", a written \\n or \\r\\n; 60 key
    characters or more make a candidate from the header to the end of the last run.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    n = len(text)
    pos = 0
    while True:
        h = _RX_PEM_HEADER.search(text, pos)
        if h is None:
            return
        p = h.end()
        count = 0
        end = -1
        while True:
            q = p
            while q < n:
                c = text[q]
                if c in _BLOCK_SKIP:
                    q += 1
                elif c == "\\" and q + 1 < n and text[q + 1] == "n":
                    q += 2
                elif c == "\\" and text.startswith("\\r\\n", q):
                    q += 4
                else:
                    break
            r = _RX_B64_RUN.match(text, q).end()
            if r - q < 16:
                break
            count += r - q
            end = r
            p = r
        if count >= 60:
            yield (h.start(), end, end)
            pos = end
        else:
            pos = h.start() + 1


def _det_openai(text: str) -> Iterator[Candidate]:
    """Detector 3: sk-... with a digit in it, not inside a word. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    def accept(m):
        """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if _guards(text, m, _not_w, _any) and _has_digit(m.group(0)):
            return (m.start(), m.end(), m.end())
        return None
    return _find_all(_RX_OPENAI, text, accept)


def _simple(rx: "re.Pattern", before_ok, after_ok) -> Callable[[str], Iterator[Candidate]]:
    """A detector made of a core regex and its two guards only. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    def det(text: str) -> Iterator[Candidate]:
        """Run the regex with its guards over text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        def accept(m):
            """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
            if _guards(text, m, before_ok, after_ok):
                return (m.start(), m.end(), m.end())
            return None
        return _find_all(rx, text, accept)
    return det


def _det_jwt(text: str) -> Iterator[Candidate]:
    """Detector 10, a JWT found by hand (linear): eyJ + a run of 8+ S characters, ".", 5+, ".", 5+.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    n = len(text)
    pos = 0
    while True:
        i = text.find("eyJ", pos)
        if i < 0:
            return
        if _is_w(_char_at(text, i - 1)):
            pos = i + 1
            continue
        j = _RX_S_RUN.match(text, i).end()
        pos = j
        if j - i >= 8 and j < n and text[j] == ".":
            k = _RX_S_RUN.match(text, j + 1).end()
            if k - (j + 1) >= 5 and k < n and text[k] == ".":
                e = _RX_S_RUN.match(text, k + 1).end()
                if e - (k + 1) >= 5:
                    yield (i, e, e)
                    pos = e


def _det_bearer(text: str) -> Iterator[Candidate]:
    """Detector 11: the token after "Bearer" (group 1), when it holds a digit or two a-z/A-Z places.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    def accept(m):
        """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        g = m.group(1)
        if _guards(text, m, _not_w, _any) and (_has_digit(g) or _lower_upper_pairs(g) >= 2):
            return (m.start(1), m.end(1), m.end())
        return None
    return _find_all(_RX_BEARER, text, accept)


def _det_url_credentials(text: str) -> Iterator[Candidate]:
    """Detector 12: the password of scheme://user:password@host (group 1), unless redacted or a placeholder.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    def accept(m):
        """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        g = m.group(1)
        if g.startswith("[REDACTED:") or ascii_lower(g) in PLACEHOLDERS:
            return None
        return (m.start(1), m.end(1), m.end())
    return _find_all(_RX_URLCRED, text, accept)


def _generic_value_end(text: str, start: int) -> int:
    """Where detector 13's value ends: the first space, tab, LF, CR, FF, VT, ' " ; or a backslash whose next
    character is one of space, tab, LF, CR, FF, VT, ' " (a backslash at the very end is taken).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    n = len(text)
    p = start
    while True:
        m = _RX_GENERIC_STOP.search(text, p)
        if m is None:
            return n
        i = m.start()
        if text[i] != "\\":
            return i
        nxt = _char_at(text, i + 1)
        if nxt is not None and nxt in _WS_STOP_AFTER_BACKSLASH:
            return i
        p = i + 1


def _det_generic(text: str) -> Iterator[Candidate]:
    """Detector 13, key = value: matched on the ASCII lower case of the text; the value is read from the
    original text and checked (not redacted, 8+ code points, not a placeholder, not a reference, looks secret).

    Kept linear on hostile input (IMPLEMENTATION RULES: detector 13 is a procedure so the scan stays linear) without
    changing any answer: a value that starts inside the previous value ends where that one ends (no stop character
    lies between them), so its end and the end of V are cached; and the checks that refuse a value in O(1) (a
    "[REDACTED:" start, the length, a $ < { % * start, a call or index) run before V is copied. Without this,
    "token=$" * 28571 took 18 s.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    lower = ascii_lower(text)
    n = len(text)
    pos = 0
    cache_vs = cache_ve = cache_vend = -1
    while pos <= n:
        m = _RX_GENERIC.search(lower, pos)
        if m is None:
            return
        s = m.start()
        run = 0
        k = s
        while k > 0 and run <= 40 and lower[k - 1] in _NAME_RUN_CHARS:
            k -= 1
            run += 1
        accepted = False
        vs = m.end()
        if run <= 40 and not text.startswith("[REDACTED:", vs):
            if 0 <= cache_vs <= vs <= cache_ve:
                ve, vend = cache_ve, max(vs, cache_vend)
            else:
                ve = _generic_value_end(text, vs)
                vend = ve
                while vend > vs and text[vend - 1] in ".,;:!?":
                    vend -= 1
                cache_vs, cache_ve, cache_vend = vs, ve, vend
            if ve - vs >= 8 and _generic_value_ok(text, vs, vend):
                yield (vs, ve, ve)
                pos = ve
                accepted = True
        if not accepted:
            pos = s + 1


_RX_PAREN = re.compile(r"[(\[]")


def _generic_value_ok(text: str, vs: int, vend: int) -> bool:
    """Detector 13's checks on V = text[vs:vend] (the value without its sentence-ending . , ; : ! ?): its ASCII
    lower case is not a PLACEHOLDER, it is not a REFERENCE, and looks_like_secret(V). The same answers as
    is_reference and looks_like_secret on the copied V; the O(1) refusals come before V is copied.

    In: the text and V's bounds. Out: bool. Why: SCREEN-05, linear scan (see _det_generic). 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if vend > vs and text[vs] in "$<{%*":
        return False
    if vend - vs <= 16 and ascii_lower(text[vs:vend]) in PLACEHOLDERS:
        return False
    p = _RX_PAREN.search(text, vs, vend)
    if p is not None and all(_is_name(part) for part in text[vs:p.start()].split(".")):
        return False
    v = text[vs:vend]
    return not is_reference(v) and looks_like_secret(v)


def _email_guard(text: str, m: "re.Match") -> bool:
    """Detector 14's guard: not inside a word, and not the user part of a URL (the nearest "/", "@" or white space
    before the match is not the end of "://"). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if not _guards(text, m, _not_w, _not_w):
        return False
    s = m.start()
    k = max(text.rfind(ch, 0, s) for ch in ("/", "@", " ", "\t", "\r", "\n"))
    if k >= 2 and text[k - 2:k + 1] == "://":
        return False
    return True


def _det_email(text: str) -> Iterator[Candidate]:
    """Detector 14, an email address. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return _find_all(_RX_EMAIL, text, lambda m: (m.start(), m.end(), m.end()) if _email_guard(text, m) else None)


def _not_digit(c: Optional[str]) -> bool:
    """The guard "is not a digit 0-9". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return not _is_digit(c)


def _luhn(digits: str) -> bool:
    """Luhn: from the last digit leftwards double every second digit (minus 9 when over 9); the sum ends in 0.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _det_card(text: str) -> Iterator[Candidate]:
    """Detector 16, a card number: the LONGEST prefix of the match with 13-19 digits, a proper end, card grouping,
    a card network prefix and a valid Luhn check. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    def accept(m):
        """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if not _not_w(_char_at(text, m.start() - 1)):
            return None
        mt = m.group(0)
        all_digits = mt.replace(" ", "").replace("-", "")
        if _RX_CARD_PREFIX.match(all_digits) is None:
            return None
        ends = []
        if not _is_w(_char_at(text, m.end())):
            ends.append(len(mt))
        for i in range(len(mt) - 1, 0, -1):
            if mt[i] == " " or mt[i] == "-":
                ends.append(i)
        for e in ends:  # longest first
            prefix = mt[:e]
            groups = re.split(r"[ -]", prefix)
            digits = "".join(groups)
            if not (13 <= len(digits) <= 19):
                continue
            if any(len(g) < 4 for g in groups[:-1]):
                continue
            if _luhn(digits):
                end = m.start() + e
                return (m.start(), end, end)
        return None
    return _find_all(_RX_CARD, text, accept)


def _det_ssn(text: str) -> Iterator[Candidate]:
    """Detector 17, a US social security number with a possible area, group and serial.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    def edge(c):
        """The SSN guard: not W and not "-". 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        return _not_w(c) and c != "-"

    def accept(m):
        """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if not _guards(text, m, edge, edge):
            return None
        a, g, s = m.group(0).split("-")
        if a == "000" or a == "666" or a[0] == "9" or g == "00" or s == "0000":
            return None
        return (m.start(), m.end(), m.end())
    return _find_all(_RX_SSN, text, accept)


def _det_ipv4(text: str) -> Iterator[Candidate]:
    """Detector 18, a public IPv4 address (not private, loopback, link-local, multicast or x.y.z.0).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    def accept(m):
        """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        before = _char_at(text, m.start() - 1)
        after = _char_at(text, m.end())
        if _is_w(before) or before == "." or _is_w(after):
            return None
        if after == "." and _is_digit(_char_at(text, m.end() + 1)):
            return None
        parts = m.group(0).split(".")
        for p in parts:
            if len(p) > 1 and p[0] == "0":
                return None
        nums = [int(p) for p in parts]
        if any(x > 255 for x in nums):
            return None
        a, b = nums[0], nums[1]
        if a in (0, 10, 127) or a >= 224:
            return None
        if (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
            return None
        if nums[3] == 0:
            return None
        return (m.start(), m.end(), m.end())
    return _find_all(_RX_IPV4, text, accept)


def _hex_group(g: str) -> bool:
    """1 to 4 hex digits. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return 1 <= len(g) <= 4 and all(c in "0123456789abcdefABCDEF" for c in g)


def _ipv6_ok(s: str) -> bool:
    """Detector 19's check: a well-formed IPv6 address whose first group is 0x2000-0x3fff (global).

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    if ":::" in s:
        return False
    c = s.count("::")
    if c > 1:
        return False
    if c == 1:
        left, right = s.split("::")
        lg = left.split(":") if left else []
        rg = right.split(":") if right else []
        if len(lg) + len(rg) > 7:
            return False
        groups = lg + rg
        if not all(_hex_group(g) for g in groups):
            return False
        first = int(lg[0], 16) if lg else 0
    else:
        groups = s.split(":")
        if len(groups) != 8 or not all(_hex_group(g) for g in groups):
            return False
        first = int(groups[0], 16)
    return 0x2000 <= first <= 0x3FFF


def _det_ipv6(text: str) -> Iterator[Candidate]:
    """Detector 19, a global IPv6 address. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    def accept(m):
        """Apply this detector's guard and check to match m. Out: (start, end, next pos) or None. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        before = _char_at(text, m.start() - 1)
        after = _char_at(text, m.end())
        if before is not None and (_is_w(before) or before in ":."):
            return None
        if after is not None and (_is_w(after) or after == ":"):
            return None
        return (m.start(), m.end(), m.end()) if _ipv6_ok(m.group(0)) else None
    return _find_all(_RX_IPV6, text, accept)


# (number, label, category, detector); the number breaks ties between candidates with the same span.
DETECTORS = [
    (1, "pem_private_key", "secret", _det_pem),
    (2, "pem_private_key", "secret", _det_pem_cut),
    (3, "openai_style_api_key", "secret", _det_openai),
    (4, "stripe_style_api_key", "secret", _simple(_RX_STRIPE, _not_w, _not_w)),
    (5, "aws_access_key_id", "secret", _simple(_RX_AWS, _not_w, _not_w)),
    (6, "github_token", "secret", _simple(_RX_GITHUB, _not_w, _not_w)),
    (7, "slack_token", "secret", _simple(_RX_SLACK, _not_w, _not_w)),
    (8, "google_api_key", "secret", _simple(_RX_GOOGLE, _not_w, lambda c: _not_w(c) and c != "-")),
    (9, "webhook_signing_secret", "secret", _simple(_RX_WHSEC, _not_w, _any)),
    (10, "jwt", "secret", _det_jwt),
    (11, "bearer_token", "secret", _det_bearer),
    (12, "url_credentials", "secret", _det_url_credentials),
    (13, "generic_key_value_assignment", "secret", _det_generic),
    (14, "email_address", "pii", _det_email),
    (15, "phone_number", "pii", _simple(_RX_PHONE, _not_digit, _not_digit)),
    (16, "credit_card_number", "pii", _det_card),
    (17, "ssn", "pii", _det_ssn),
    (18, "ip_address", "pii", _det_ipv4),
    (19, "ip_address", "pii", _det_ipv6),
]


class ScreeningConfigError(Exception):
    """Construction refused (fail closed): code "invalid_hash_key". The message never holds the key.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, code: str):
        """In: the error code. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        super().__init__(code)
        self.code = code


def _refusal(error: str, status: int, findings: Optional[List[dict]] = None) -> dict:
    """A refusal dict {ok: false, error, status[, findings]}; it never carries the text.

    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    out = {"ok": False, "error": error, "status": status}
    if findings is not None:
        out["findings"] = findings
    return out


class Screener:
    """A configured screener: an optional HMAC key for value_hash and the max text size in UTF-8 bytes.

    Why: new_screener of the spec. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""

    def __init__(self, hash_key=None, max_bytes: int = DEFAULT_MAX_BYTES):
        """In: hash_key (bytes, or str taken as UTF-8; at least 32 bytes) or None; max_bytes. Raises
        ScreeningConfigError("invalid_hash_key") for a short key. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        if hash_key is not None:
            if isinstance(hash_key, str):
                hash_key = hash_key.encode("utf-8")
            if not isinstance(hash_key, (bytes, bytearray)) or len(hash_key) < 32:
                raise ScreeningConfigError("invalid_hash_key")
            hash_key = bytes(hash_key)
        self._hash_key = hash_key
        self.max_bytes = max_bytes

    def _value_hash(self, value: str) -> Optional[str]:
        """Lower-case hex HMAC-SHA256(hash_key, UTF-8 of value), or None without a key.

        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if self._hash_key is None:
            return None
        return hmac.new(self._hash_key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def scan_text(self, text: str, categories: Optional[Sequence[str]] = None) -> List[dict]:
        """scan_text: run the detectors of the given categories, combine (earliest start, then longest span, then
        lowest detector number; no character in two findings) and return the findings ordered by start.

        In: text, categories (default both). Out: [finding]. Why: SCREEN-02..08, SCREEN-11.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        cats = set(ALL_CATEGORIES if categories is None else categories)
        cands = []
        for number, label, category, det in DETECTORS:
            if category not in cats:
                continue
            for (s, e, _nxt) in det(text):
                cands.append((s, -(e - s), number, e, label, category))
        cands.sort(key=lambda c: (c[0], c[1], c[2]))
        out: List[dict] = []
        last_end = 0
        for s, _neg, _num, e, label, category in cands:
            if s >= last_end:
                value = text[s:e]
                out.append({"category": category, "label": label, "start": s, "end": e,
                            "preview": mask(value), "value_hash": self._value_hash(value), "encoded": False})
                last_end = e
        return out

    def screen_text(self, text, mode="reject", categories=None) -> dict:
        """screen_text: the entry point, steps 1-10 of the spec in order; the first that answers ends the call.

        In: text, mode "reject" | "strip", categories (default ["secret", "pii"]). Out: {ok: true, status: 200,
        text, findings} or a refusal {ok: false, error, status[, findings]}. Anything raised while scanning is
        500 screening_failed (fail closed). Why: SCREEN-09, 10, 13, 14. 2026-11-10,
        session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
        if not isinstance(text, str):
            return _refusal("invalid_text", 400)
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError:
            return _refusal("invalid_text", 400)
        if not isinstance(mode, str) or mode not in ("reject", "strip"):
            return _refusal("invalid_mode", 400)
        if categories is None:
            categories = list(ALL_CATEGORIES)
        if (not isinstance(categories, (list, tuple)) or len(categories) == 0
                or any(not isinstance(c, str) or c not in ALL_CATEGORIES for c in categories)):
            return _refusal("invalid_categories", 400)
        if len(encoded) > self.max_bytes:
            return _refusal("text_too_large", 413)
        try:
            found = self.scan_text(text, categories)
            if mode == "reject" and found:
                return _refusal("secrets_or_pii_detected", 422, found)
            out = redact_text(text, found) if found else text
            if mode == "strip" and found:
                again = self.scan_text(out, categories)
                if again:
                    return _refusal("secrets_or_pii_detected", 422,
                                    found + [dict(f, start=-1, end=-1) for f in again])
            if "\\" in out:
                r = resolve_escapes(out)
                hidden: List[dict] = []
                if r["text"] != out:
                    hidden = [dict(f, encoded=True, start=-1, end=-1) for f in self.scan_text(r["text"], categories)]
                if r["unresolved"]:
                    hidden.append({"category": "secret", "label": "unresolved_escape", "start": -1, "end": -1,
                                   "preview": "***", "value_hash": None, "encoded": True})
                if hidden:
                    return _refusal("secrets_or_pii_detected", 422, found + hidden)
            return {"ok": True, "status": 200, "text": out, "findings": found}
        except Exception:  # noqa: BLE001 - fail closed: never "nothing found", never an unhandled exception
            return _refusal("screening_failed", 500)


def new_screener(hash_key=None, max_bytes: int = DEFAULT_MAX_BYTES) -> Screener:
    """new_screener(hash_key = none, max_bytes = 1048576) -> a Screener; a key under 32 bytes raises
    ScreeningConfigError("invalid_hash_key") and no screener exists.

    Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    return Screener(hash_key=hash_key, max_bytes=max_bytes)
