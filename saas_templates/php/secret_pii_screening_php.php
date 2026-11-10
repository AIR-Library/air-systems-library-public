<?php
/**
 * Secret & PII screening (docs/specs/secret_pii_screening.md).
 *
 * What it does: finds secrets (API keys, tokens, private keys, passwords in URLs and in assignments) and
 * personal data (email addresses, phone numbers, card numbers, IP addresses, US social security numbers) in a
 * text BEFORE it is stored, logged or shared, and either refuses the text ("reject") or replaces each match
 * with a [REDACTED:<label>] marker ("strip"). Escaped text (JSON \uXXXX, \n ...) is resolved and screened
 * again, so a secret hidden behind an escape is refused in both modes.
 *
 * Inputs/outputs: Screener::screenText() returns {ok, status, text?, findings?, error?}; a refusal is a
 * returned array, never an exception. Offsets count Unicode code points (PHP regexes report bytes, so every
 * offset is converted before it is returned).
 *
 * Why: Phase D wave 1, owner request 2026-11-10 (spec ids SCREEN-01..14).
 * Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only. No database, no files, no network, no money. Never logs the text, a matched value or
 * the hash key.
 */

declare(strict_types=1);

namespace SecretPiiScreening;

use RuntimeException;
use Throwable;

/**
 * Raised only when a Screener cannot be built (a hash key shorter than 32 bytes).
 *
 * Inputs: the error code. Output: an exception whose getErrorCode() is that code; the message never holds
 * the key. Why: SCREEN-12 (a short key fails construction, fail closed). 2026-11-10,
 * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
final class ScreeningError extends RuntimeException
{
    private string $errorCode;

    /**
     * Build the error. In: the spec's error code (e.g. "invalid_hash_key"). Out: the exception.
     * Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function __construct(string $errorCode)
    {
        parent::__construct($errorCode);
        $this->errorCode = $errorCode;
    }

    /**
     * The spec's error code. In: nothing. Out: e.g. "invalid_hash_key".
     * Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }
}

/**
 * Build a screener (spec: new_screener). In: the server's hash key (null = every value_hash is null) and the
 * largest text in UTF-8 bytes. Out: a Screener. Throws ScreeningError("invalid_hash_key") for a key under 32
 * bytes. Why: SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function new_screener(?string $hashKey = null, int $maxBytes = 1048576): Screener
{
    return new Screener($hashKey, $maxBytes);
}

/**
 * mask(value): n < 16 code points -> n stars; otherwise the first 2 characters, n - 4 stars, the last 2.
 * In: a well-formed UTF-8 string. Out: the preview. Why: SCREEN-12 (a preview never shows a short secret).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
 */
function mask(string $value): string
{
    preg_match_all('/./us', $value, $m);
    $chars = $m[0];
    $n = count($chars);
    if ($n < 16) {
        return str_repeat('*', $n);
    }
    return $chars[0] . $chars[1] . str_repeat('*', $n - 4) . $chars[$n - 2] . $chars[$n - 1];
}

/**
 * resolve_escapes(text): repeat one left-to-right escape pass while the text holds an ESCAPE, at most 8 times.
 * In: a UTF-8 string. Out: {text, unresolved} where unresolved = an ESCAPE is left after the 8th pass.
 * Why: SCREEN-13 (a secret hidden behind JSON escapes). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing.
 */
function resolve_escapes(string $text): array
{
    $passes = 0;
    while ($passes < 8 && Screener::holdsEscape($text)) {
        $text = Screener::escapePass($text);
        $passes++;
    }
    return ['text' => $text, 'unresolved' => Screener::holdsEscape($text)];
}

/**
 * The screener: detectors, combining, redaction and the screen_text steps of the spec.
 *
 * Inputs: an optional hash key (>= 32 bytes) and max_bytes. Outputs: see each method.
 * Why: SCREEN-01..14, Phase D wave 1, owner request 2026-11-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: memory only.
 */
final class Screener
{
    /** Delimiter '#' never appears in a core regex; no flags (no i, no u, no m), per MATCHING. */
    private const HEADER_RE = '#-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----#';

    /**
     * The regex detectors: number => [label, category, regex, kind]. Numbers 2 and 10 are procedures, 13 is
     * matched on the ASCII lower case of the text; 11 and 12 take capture group 1 as their span.
     */
    private const REGEX = [
        1 => ['pem_private_key', 'secret', '#-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\r?\n)?[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----#'],
        3 => ['openai_style_api_key', 'secret', '#sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]#'],
        4 => ['stripe_style_api_key', 'secret', '#[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}#'],
        5 => ['aws_access_key_id', 'secret', '#A[KS]IA[0-9A-Z]{16}#'],
        6 => ['github_token', 'secret', '#gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}#'],
        7 => ['slack_token', 'secret', '#xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]#'],
        8 => ['google_api_key', 'secret', '#AIza[0-9A-Za-z_-]{35}#'],
        9 => ['webhook_signing_secret', 'secret', '#whsec_[A-Za-z0-9+/=]{16,500}#'],
        11 => ['bearer_token', 'secret', '#[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})#'],
        12 => ['url_credentials', 'secret', '#[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@#'],
        13 => ['generic_key_value_assignment', 'secret', '#(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key|credentials?|token)(?:\\\\?["\'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\\\?["\'])?#'],
        14 => ['email_address', 'pii', '#[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}#'],
        15 => ['phone_number', 'pii', '#(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}#'],
        16 => ['credit_card_number', 'pii', '#[0-9](?:[ -]?[0-9]){12,18}#'],
        17 => ['ssn', 'pii', '#[0-9]{3}-[0-9]{2}-[0-9]{4}#'],
        18 => ['ip_address', 'pii', '#[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}#'],
        19 => ['ip_address', 'pii', '#[0-9A-Fa-f:]{2,39}#'],
    ];

    private const PLACEHOLDERS = [
        'changeme', 'change_me', 'your_key_here', 'your-key-here', 'xxx', 'xxxx', 'xxxxx', 'redacted', 'todo',
        'example', 'placeholder', 'secret', 'password', 'insert_key_here', 'none', 'null', 'n/a', 'na',
        '<your-password>', '<your-key>', 'fillmein',
    ];

    private const CARD_PREFIX = '#^(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])#';

    private const ESCAPE_RE = '#\\\\(?:u[0-9A-Fa-f]{4}|["\\\\/bfnrt])#';

    private ?string $hashKey;
    private int $maxBytes;

    /**
     * Build a screener. In: hash key (null or >= 32 bytes) and max_bytes. Out: the screener.
     * Throws ScreeningError("invalid_hash_key") for a shorter key: no screener exists (fail closed).
     * Why: SCREEN-12, SCREEN-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public function __construct(?string $hashKey = null, int $maxBytes = 1048576)
    {
        if ($hashKey !== null && strlen($hashKey) < 32) {
            throw new ScreeningError('invalid_hash_key');
        }
        $this->hashKey = $hashKey;
        $this->maxBytes = $maxBytes;
    }

    /**
     * screen_text: the entry point, steps 1-10 of the spec in order (the first that answers ends the call).
     *
     * In: text, mode ("reject" default, or "strip"), categories (default ["secret", "pii"]).
     * Out: {ok: true, status: 200, text, findings} or {ok: false, error, status[, findings]}; a refusal never
     * carries text. Anything raised inside a detector or the hidden check is screening_failed 500.
     * Why: SCREEN-09, SCREEN-10, SCREEN-13, SCREEN-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    public function screenText(string $text, string $mode = 'reject', array $categories = ['secret', 'pii']): array
    {
        if (preg_match('//u', $text) !== 1) {
            return ['ok' => false, 'error' => 'invalid_text', 'status' => 400];
        }
        if ($mode !== 'reject' && $mode !== 'strip') {
            return ['ok' => false, 'error' => 'invalid_mode', 'status' => 400];
        }
        if ($categories === []) {
            return ['ok' => false, 'error' => 'invalid_categories', 'status' => 400];
        }
        foreach ($categories as $c) {
            if ($c !== 'secret' && $c !== 'pii') {
                return ['ok' => false, 'error' => 'invalid_categories', 'status' => 400];
            }
        }
        if (strlen($text) > $this->maxBytes) {
            return ['ok' => false, 'error' => 'text_too_large', 'status' => 413];
        }
        try {
            $raw = $this->scanRaw($text, $categories);
            $f = $this->toFindings($text, $raw);
            if ($mode === 'reject' && $f !== []) {
                return ['ok' => false, 'error' => 'secrets_or_pii_detected', 'status' => 422, 'findings' => $f];
            }
            $out = $f === [] ? $text : self::redactRaw($text, $raw);
            if ($mode === 'strip' && $f !== []) {
                $f2 = $this->scanText($out, $categories);
                if ($f2 !== []) {
                    foreach ($f2 as &$x) {
                        $x['start'] = -1;
                        $x['end'] = -1;
                    }
                    unset($x);
                    return ['ok' => false, 'error' => 'secrets_or_pii_detected', 'status' => 422,
                        'findings' => array_merge($f, $f2)];
                }
            }
            if (strpos($out, '\\') !== false) {
                $r = resolve_escapes($out);
                $h = [];
                if ($r['text'] !== $out) {
                    foreach ($this->scanText($r['text'], $categories) as $x) {
                        $x['start'] = -1;
                        $x['end'] = -1;
                        $x['encoded'] = true;
                        $h[] = $x;
                    }
                }
                if ($r['unresolved']) {
                    $h[] = ['category' => 'secret', 'label' => 'unresolved_escape', 'start' => -1, 'end' => -1,
                        'preview' => '***', 'value_hash' => null, 'encoded' => true];
                }
                if ($h !== []) {
                    return ['ok' => false, 'error' => 'secrets_or_pii_detected', 'status' => 422,
                        'findings' => array_merge($f, $h)];
                }
            }
            return ['ok' => true, 'status' => 200, 'text' => $out, 'findings' => $f];
        } catch (Throwable $e) {
            // Fail closed; the exception (which could quote input) is never logged or returned.
            return ['ok' => false, 'error' => 'screening_failed', 'status' => 500];
        }
    }

    /**
     * scan_text: every finding of the detectors in the given categories, ordered by start.
     * In: a well-formed UTF-8 text, categories. Out: [finding] with code-point start/end, preview, value_hash,
     * encoded false. Throws on a regex engine error (screenText turns that into screening_failed).
     * Why: SCREEN-02..08, SCREEN-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public function scanText(string $text, array $categories = ['secret', 'pii']): array
    {
        return $this->toFindings($text, $this->scanRaw($text, $categories));
    }

    /**
     * redact_text: each finding's span replaced by "[REDACTED:" + label + "]", in one left-to-right pass.
     * In: the text and findings (code-point start/end; findings with start -1 are skipped). Out: the new text.
     * Why: SCREEN-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public function redactText(string $text, array $findings): string
    {
        $offsets = [];
        foreach ($findings as $f) {
            if ($f['start'] >= 0) {
                $offsets[] = $f['start'];
                $offsets[] = $f['end'];
            }
        }
        $map = self::cpToByte($text, $offsets);
        $raw = [];
        foreach ($findings as $f) {
            if ($f['start'] >= 0) {
                $raw[] = ['s' => $map[$f['start']], 'e' => $map[$f['end']], 'label' => $f['label']];
            }
        }
        usort($raw, static fn(array $a, array $b): int => $a['s'] <=> $b['s']);
        return self::redactRaw($text, $raw);
    }

    /**
     * True when the text holds an ESCAPE (\uXXXX or a backslash before one of " \ / b f n r t).
     * In: text. Out: bool. Why: SCREEN-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static function holdsEscape(string $text): bool
    {
        return preg_match(self::ESCAPE_RE, $text) === 1;
    }

    /**
     * One escape pass, left to right (spec ESCAPES): \uXXXX -> the character (a high + low surrogate pair ->
     * one character, any other surrogate -> U+FFFD), \" \\ \/ -> " \ /, \b \f \n \r \t -> their controls;
     * any other backslash stays. In: UTF-8 text. Out: UTF-8 text.
     * Why: SCREEN-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static function escapePass(string $t): string
    {
        $simple = ['"' => '"', '\\' => '\\', '/' => '/', 'b' => "\x08", 'f' => "\x0C", 'n' => "\n", 'r' => "\r", 't' => "\t"];
        $out = '';
        $n = strlen($t);
        $i = 0;
        while ($i < $n) {
            $p = strpos($t, '\\', $i);
            if ($p === false) {
                $out .= substr($t, $i);
                break;
            }
            $out .= substr($t, $i, $p - $i);
            $next = $p + 1 < $n ? $t[$p + 1] : '';
            if ($next === 'u' && self::hex4($t, $p + 2)) {
                $cp = hexdec(substr($t, $p + 2, 4));
                $i = $p + 6;
                if ($cp >= 0xD800 && $cp <= 0xDBFF && $i + 1 < $n && $t[$i] === '\\' && $t[$i + 1] === 'u' && self::hex4($t, $i + 2)) {
                    $lo = hexdec(substr($t, $i + 2, 4));
                    if ($lo >= 0xDC00 && $lo <= 0xDFFF) {
                        $out .= self::utf8(0x10000 + (($cp - 0xD800) << 10) + ($lo - 0xDC00));
                        $i += 6;
                        continue;
                    }
                }
                $out .= ($cp >= 0xD800 && $cp <= 0xDFFF) ? self::utf8(0xFFFD) : self::utf8($cp);
                continue;
            }
            if ($next !== '' && isset($simple[$next])) {
                $out .= $simple[$next];
                $i = $p + 2;
                continue;
            }
            $out .= '\\';
            $i = $p + 1;
        }
        return $out;
    }

    // ------------------------------------------------------------------------------------------- internals

    /**
     * True when the 4 bytes at $at are hex digits. In: text, byte offset. Out: bool.
     * Why: SCREEN-13 escape pass. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function hex4(string $t, int $at): bool
    {
        return $at + 4 <= strlen($t) && strspn($t, '0123456789abcdefABCDEF', $at, 4) === 4;
    }

    /**
     * UTF-8 bytes of one code point. In: a code point (not a surrogate). Out: its bytes.
     * Why: SCREEN-13 escape pass (no mbstring needed). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    private static function utf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    /**
     * Run the detectors and combine (spec COMBINING). In: text, categories. Out: kept candidates
     * [{s, e (byte offsets), label, category}] ordered by start. Throws on a regex engine error.
     * Why: SCREEN-02..08, SCREEN-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    private function scanRaw(string $text, array $categories): array
    {
        $wantSecret = in_array('secret', $categories, true);
        $wantPii = in_array('pii', $categories, true);
        $cands = [];
        $lower = strtr($text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
        for ($d = 1; $d <= 19; $d++) {
            $isSecret = $d <= 13;
            if (($isSecret && !$wantSecret) || (!$isSecret && !$wantPii)) {
                continue;
            }
            if ($d === 2) {
                $found = $this->cutOffPem($text);
            } elseif ($d === 10) {
                $found = $this->jwt($text);
            } elseif ($d === 13) {
                $found = $this->generic($text, $lower);
            } else {
                $found = $this->findAll($d, $text);
            }
            foreach ($found as [$s, $e]) {
                $label = $d === 2 ? 'pem_private_key' : ($d === 10 ? 'jwt' : self::REGEX[$d][0]);
                $cands[] = ['s' => $s, 'e' => $e, 'd' => $d, 'label' => $label, 'category' => $isSecret ? 'secret' : 'pii'];
            }
        }
        usort($cands, static function (array $a, array $b): int {
            return [$a['s'], $b['e'] - $b['s'], $a['d']] <=> [$b['s'], $a['e'] - $a['s'], $b['d']];
        });
        $kept = [];
        $lastEnd = 0;
        foreach ($cands as $c) {
            if ($c['s'] >= $lastEnd) {
                $kept[] = $c;
                $lastEnd = $c['e'];
            }
        }
        return $kept;
    }

    /**
     * The leftmost match of a regex at or after $pos. In: regex, text, byte offset. Out: null or
     * [start, end, g1start, g1end] (g1 -1 when there is no group 1). Throws on an engine error (fail closed).
     * Why: MATCHING find_all. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function match(string $re, string $text, int $pos): ?array
    {
        $r = preg_match($re, $text, $m, PREG_OFFSET_CAPTURE, $pos);
        if ($r === false) {
            throw new RuntimeException('regex engine error ' . preg_last_error());
        }
        if ($r === 0) {
            return null;
        }
        $s = $m[0][1];
        $e = $s + strlen($m[0][0]);
        if (isset($m[1]) && $m[1][1] >= 0) {
            return [$s, $e, $m[1][1], $m[1][1] + strlen($m[1][0])];
        }
        return [$s, $e, -1, -1];
    }

    /**
     * True when the byte is in W = [A-Za-z0-9_]. In: one byte or '' (none). Out: bool. none is not in W.
     * Why: MATCHING guards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function isW(string $c): bool
    {
        return $c !== '' && (ctype_alnum($c) || $c === '_') && ord($c) < 0x80;
    }

    /**
     * True when the byte is a digit 0-9. In: one byte or ''. Out: bool.
     * Why: MATCHING guards. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function isDigit(string $c): bool
    {
        return $c !== '' && $c >= '0' && $c <= '9' && strlen($c) === 1;
    }

    /**
     * find_all for the regex detectors (all but 2, 10 and 13): guard and check, then candidate or pos+1.
     * In: detector number, text. Out: [[start, end]] byte spans. Why: MATCHING, DETECTORS 1, 3-9, 11, 12, 14-19.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function findAll(int $d, string $text): array
    {
        $re = self::REGEX[$d][2];
        $n = strlen($text);
        $out = [];
        $pos = 0;
        while ($pos <= $n) {
            $m = self::match($re, $text, $pos);
            if ($m === null) {
                break;
            }
            [$s, $e, $g1s, $g1e] = $m;
            $before = $s > 0 ? $text[$s - 1] : '';
            $after = $e < $n ? $text[$e] : '';
            $span = $this->accept($d, $text, $s, $e, $g1s, $g1e, $before, $after);
            if ($span !== null) {
                $out[] = $span;
                $pos = $e;
                if ($d === 16) {
                    $pos = $span[1];
                }
                if ($e === $s) {
                    $pos++;
                }
            } else {
                $pos = $s + 1;
            }
        }
        return $out;
    }

    /**
     * Guard and check of one regex detector. In: detector, text, match span, group 1 span, before/after
     * bytes. Out: the candidate span [start, end] or null. Why: DETECTORS. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function accept(int $d, string $text, int $s, int $e, int $g1s, int $g1e, string $before, string $after): ?array
    {
        $m = substr($text, $s, $e - $s);
        switch ($d) {
            case 1:
                return [$s, $e];
            case 3:
                return (!self::isW($before) && strpbrk($m, '0123456789') !== false) ? [$s, $e] : null;
            case 4:
            case 5:
            case 6:
            case 7:
                return (!self::isW($before) && !self::isW($after)) ? [$s, $e] : null;
            case 8:
                return (!self::isW($before) && !self::isW($after) && $after !== '-') ? [$s, $e] : null;
            case 9:
                return !self::isW($before) ? [$s, $e] : null;
            case 11:
                if (self::isW($before)) {
                    return null;
                }
                $g = substr($text, $g1s, $g1e - $g1s);
                return (strpbrk($g, '0123456789') !== false || self::caseHumps($g) >= 2) ? [$g1s, $g1e] : null;
            case 12:
                $g = substr($text, $g1s, $g1e - $g1s);
                if (strncmp($g, '[REDACTED:', 10) === 0 || self::isPlaceholder($g)) {
                    return null;
                }
                return [$g1s, $g1e];
            case 14:
                if (self::isW($before) || self::isW($after)) {
                    return null;
                }
                $k = $s - 1;
                while ($k >= 0 && strpos("/@ \t\r\n", $text[$k]) === false) {
                    $k--;
                }
                if ($k >= 2 && substr($text, $k - 2, 3) === '://') {
                    return null;
                }
                return [$s, $e];
            case 15:
                return (!self::isDigit($before) && !self::isDigit($after)) ? [$s, $e] : null;
            case 16:
                return self::isW($before) ? null : self::card($text, $s, $e, $after);
            case 17:
                if (self::isW($before) || $before === '-' || self::isW($after) || $after === '-') {
                    return null;
                }
                [$a, $b, $c] = explode('-', $m);
                if ($a === '000' || $a === '666' || $a[0] === '9' || $b === '00' || $c === '0000') {
                    return null;
                }
                return [$s, $e];
            case 18:
                if (self::isW($before) || $before === '.' || self::isW($after)) {
                    return null;
                }
                if ($after === '.' && $e + 1 < strlen($text) && self::isDigit($text[$e + 1])) {
                    return null;
                }
                return self::publicIpv4($m) ? [$s, $e] : null;
            case 19:
                if ($before !== '' && (self::isW($before) || $before === ':' || $before === '.')) {
                    return null;
                }
                if ($after !== '' && (self::isW($after) || $after === ':')) {
                    return null;
                }
                return self::globalIpv6($m) ? [$s, $e] : null;
        }
        return null;
    }

    /**
     * Places where a letter a-z is directly followed by a letter A-Z. In: text. Out: count.
     * Why: detector 11 check and looks_like_secret. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function caseHumps(string $v): int
    {
        return preg_match_all('#[a-z](?=[A-Z])#', $v);
    }

    /**
     * True when the ASCII lower case of the value is a PLACEHOLDER. In: value. Out: bool.
     * Why: detectors 12 and 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function isPlaceholder(string $v): bool
    {
        return in_array(strtr($v, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), self::PLACEHOLDERS, true);
    }

    /**
     * Detector 16's span: the longest prefix of m that holds 13-19 digits, ends at m's end (after not W) or
     * just before a space or "-" inside m, is grouped like a card, starts with a CARD PREFIX and passes Luhn.
     * In: text, match span, after byte. Out: [start, end] or null.
     * Why: SCREEN-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function card(string $text, int $s, int $e, string $after): ?array
    {
        $m = substr($text, $s, $e - $s);
        $allDigits = str_replace([' ', '-'], '', $m);
        if (preg_match(self::CARD_PREFIX, $allDigits) !== 1) {
            return null;
        }
        $ends = [];
        if (!self::isW($after)) {
            $ends[] = strlen($m);
        }
        for ($i = strlen($m) - 1; $i > 0; $i--) {
            if ($m[$i] === ' ' || $m[$i] === '-') {
                $ends[] = $i;
            }
        }
        foreach ($ends as $len) {
            $prefix = substr($m, 0, $len);
            $groups = preg_split('#[ -]#', $prefix);
            $digits = implode('', $groups);
            $nd = strlen($digits);
            if ($nd < 13 || $nd > 19) {
                continue;
            }
            $ok = true;
            for ($g = 0; $g < count($groups) - 1; $g++) {
                if (strlen($groups[$g]) < 4) {
                    $ok = false;
                    break;
                }
            }
            if ($ok && self::luhn($digits)) {
                return [$s, $s + $len];
            }
        }
        return null;
    }

    /**
     * Luhn check. In: a digit string. Out: bool. Why: SCREEN-07. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    private static function luhn(string $digits): bool
    {
        $sum = 0;
        $double = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $v = ord($digits[$i]) - 48;
            if ($double) {
                $v *= 2;
                if ($v > 9) {
                    $v -= 9;
                }
            }
            $sum += $v;
            $double = !$double;
        }
        return $sum % 10 === 0;
    }

    /**
     * Detector 18's check: four numbers 0-255 with no leading zero, and a public host address.
     * In: dotted text. Out: bool. Why: SCREEN-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function publicIpv4(string $m): bool
    {
        $p = explode('.', $m);
        $n = [];
        foreach ($p as $x) {
            if ((strlen($x) > 1 && $x[0] === '0') || (int)$x > 255) {
                return false;
            }
            $n[] = (int)$x;
        }
        if ($n[0] === 0 || $n[0] === 10 || $n[0] === 127 || $n[0] >= 224) {
            return false;
        }
        if (($n[0] === 169 && $n[1] === 254) || ($n[0] === 172 && $n[1] >= 16 && $n[1] <= 31) || ($n[0] === 192 && $n[1] === 168)) {
            return false;
        }
        return $n[3] !== 0;
    }

    /**
     * Detector 19's check: a well-formed IPv6 address whose first group is 0x2000-0x3fff (global unicast).
     * In: text of [0-9A-Fa-f:]. Out: bool. Why: SCREEN-08. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    private static function globalIpv6(string $m): bool
    {
        if (strpos($m, ':::') !== false || substr_count($m, '::') > 1) {
            return false;
        }
        if (strpos($m, '::') !== false) {
            [$l, $r] = explode('::', $m, 2);
            $left = $l === '' ? [] : explode(':', $l);
            $right = $r === '' ? [] : explode(':', $r);
            if (count($left) + count($right) > 7) {
                return false;
            }
            $groups = array_merge($left, $right);
            $first = $l === '' ? 0 : null;
        } else {
            $groups = explode(':', $m);
            if (count($groups) !== 8) {
                return false;
            }
            $first = null;
        }
        foreach ($groups as $g) {
            if (strlen($g) < 1 || strlen($g) > 4) {
                return false;
            }
        }
        if ($first === null) {
            $first = hexdec($groups[0]);
        }
        return $first >= 0x2000 && $first <= 0x3fff;
    }

    /**
     * Detector 2: a private key block cut off before its END line, found by hand (no repeated group).
     * In: text. Out: [[start, end]] byte spans. Why: SCREEN-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    private function cutOffPem(string $text): array
    {
        $n = strlen($text);
        $out = [];
        $pos = 0;
        while ($pos <= $n) {
            $h = self::match(self::HEADER_RE, $text, $pos);
            if ($h === null) {
                break;
            }
            $p = $h[1];
            $count = 0;
            $end = -1;
            while (true) {
                $q = $p;
                while ($q < $n) {
                    $c = $text[$q];
                    if ($c === ' ' || $c === "\t" || $c === "\r" || $c === "\n" || $c === '>' || $c === '-') {
                        $q++;
                    } elseif ($c === '\\' && $q + 1 < $n && $text[$q + 1] === 'n') {
                        $q += 2;
                    } elseif ($c === '\\' && $q + 3 < $n && substr($text, $q, 4) === '\\r\\n') {
                        $q += 4;
                    } else {
                        break;
                    }
                }
                $len = $q < $n ? strspn($text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', $q) : 0;
                if ($len < 16) {
                    break;
                }
                $count += $len;
                $end = $q + $len;
                $p = $end;
            }
            if ($count >= 60) {
                $out[] = [$h[0], $end];
                $pos = $end;
            } else {
                $pos = $h[0] + 1;
            }
        }
        return $out;
    }

    /**
     * Detector 10: a JWT, found by hand so it is linear. In: text. Out: [[start, end]] byte spans.
     * Why: SCREEN-02, SCREEN-04. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function jwt(string $text): array
    {
        $sChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
        $n = strlen($text);
        $out = [];
        $pos = 0;
        while ($pos < $n) {
            $i = strpos($text, 'eyJ', $pos);
            if ($i === false) {
                break;
            }
            if ($i > 0 && self::isW($text[$i - 1])) {
                $pos = $i + 1;
                continue;
            }
            $j = $i + strspn($text, $sChars, $i);
            $pos = $j;
            if ($j - $i < 8 || $j >= $n || $text[$j] !== '.') {
                continue;
            }
            $r2 = $j + 1 < $n ? strspn($text, $sChars, $j + 1) : 0;
            if ($r2 < 5) {
                continue;
            }
            $k = $j + 1 + $r2;
            if ($k >= $n || $text[$k] !== '.') {
                continue;
            }
            $r3 = $k + 1 < $n ? strspn($text, $sChars, $k + 1) : 0;
            if ($r3 < 5) {
                continue;
            }
            $e = $k + 1 + $r3;
            $out[] = [$i, $e];
            $pos = $e;
        }
        return $out;
    }

    /**
     * Detector 13: key = value assignments, matched on the ASCII lower case; the value is read from the
     * original text. In: text, its ASCII lower case. Out: [[start, end]] byte spans of values.
     * 2026-11-10 (session_012zDydZCZ4AChqhEZ4oVtaP, SCREEN-14 "token=$" * 28571): value ends come from one cached
     * forward scan and the instant refusals (under 8 bytes, a leading $ < { % *, a call or index) run first;
     * answers unchanged.
     * Why: SCREEN-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function generic(string $text, string $lower): array
    {
        $re = self::REGEX[13][2];
        $n = strlen($text);
        $out = [];
        $pos = 0;
        $scanFrom = 1;
        $scanEnd = 0;
        while ($pos <= $n) {
            $m = self::match($re, $lower, $pos);
            if ($m === null) {
                break;
            }
            [$s, $e] = $m;
            $run = 0;
            for ($k = $s - 1; $k >= 0 && $run <= 40; $k--) {
                $c = $lower[$k];
                if (($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9') || $c === '_' || $c === '.' || $c === '-') {
                    $run++;
                } else {
                    break;
                }
            }
            if ($run > 40 || strncmp(substr($text, $e, 10), '[REDACTED:', 10) === 0) {
                $pos = $s + 1;
                continue;
            }
            // Where the value ends depends only on the text from $e on, and $e only grows, so one forward scan
            // serves every match whose $e lies inside it (2026-11-10 note in the spec: stay linear).
            if ($e < $scanFrom || $e > $scanEnd) {
                $scanFrom = $e;
                $scanEnd = self::valueEnd($text, $e);
            }
            $v = $scanEnd;
            $len = $v - $e;
            // The instant refusals first (each one refuses, as the spec's later checks would): under 8 bytes is
            // under 8 code points; a value whose first character is $ < { % * is a REFERENCE (that character
            // is never trimmed as sentence punctuation, so V starts with it too). Answers do not change.
            if ($len < 8 || strpos('$<{%*', $text[$e]) !== false) {
                $pos = $s + 1;
                continue;
            }
            // A call or an index (NAMEs before the first "(" or "[") is a REFERENCE too; neither character is
            // trimmed, so the test on the value equals the test on V. Read in place, without copying the value.
            $cut = strcspn($text, '([', $e, $len);
            if ($cut < $len && self::namesOnly(substr($text, $e, $cut))) {
                $pos = $s + 1;
                continue;
            }
            $value = substr($text, $e, $len);
            if ($len >= 32 || self::cpLen($value) >= 8) {
                $core = rtrim($value, '.,;:!?');
                if (!self::isPlaceholder($core) && !self::isReference($core) && self::looksLikeSecret($core)) {
                    $out[] = [$e, $v];
                    $pos = $v;
                    continue;
                }
            }
            $pos = $s + 1;
        }
        return $out;
    }

    /**
     * Where detector 13's value starting at $from ends: the first of space, tab, LF, CR, FF, VT, ' " ; or a
     * backslash followed by space, tab, LF, CR, FF, VT, ' or " (a backslash at the very end is taken), else the
     * end of the text. Uses strcspn, so a scan costs its length once.
     * In: text, byte offset. Out: byte offset of the end. Why: SCREEN-14 ("token=$" * 28571 must stay linear;
     * spec note 2026-11-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function valueEnd(string $text, int $from): int
    {
        $n = strlen($text);
        $v = $from;
        while ($v < $n) {
            $v += strcspn($text, " \t\n\r\f\v'\";\\", $v);
            if ($v >= $n || $text[$v] !== '\\') {
                return $v;
            }
            if ($v + 1 < $n && strpos(" \t\n\r\f\v'\"", $text[$v + 1]) !== false) {
                return $v;
            }
            $v++;
        }
        return $n;
    }

    /**
     * looks_like_secret: a digit 0-9, or an ASCII character outside [A-Za-z0-9], or 2+ a-z->A-Z humps.
     * In: value. Out: bool. Why: detector 13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function looksLikeSecret(string $v): bool
    {
        if (strpbrk($v, '0123456789') !== false) {
            return true;
        }
        if (preg_match('#[\x00-\x2F\x3A-\x40\x5B-\x60\x7B-\x7F]#', $v) === 1) {
            return true;
        }
        return self::caseHumps($v) >= 2;
    }

    /**
     * True when the text is a NAME: [A-Za-z_] then [A-Za-z0-9_]*. In: text. Out: bool.
     * Why: REFERENCE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function isName(string $s): bool
    {
        if ($s === '') {
            return false;
        }
        $c = $s[0];
        if (!(($c >= 'A' && $c <= 'Z') || ($c >= 'a' && $c <= 'z') || $c === '_')) {
            return false;
        }
        return strspn($s, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_') === strlen($s);
    }

    /**
     * True when every "."-separated part is a NAME. In: text. Out: bool.
     * Why: REFERENCE. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function namesOnly(string $s): bool
    {
        foreach (explode('.', $s) as $part) {
            if (!self::isName($part)) {
                return false;
            }
        }
        return true;
    }

    /**
     * REFERENCE(V): a variable, template or mask ($ < { % *), a call or index (NAMEs before the first ( or [),
     * or a dotted name with no digit. Written as loops, not a regex. In: V. Out: bool.
     * Why: SCREEN-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function isReference(string $v): bool
    {
        if ($v !== '' && strpos('$<{%*', $v[0]) !== false) {
            return true;
        }
        $cut = strcspn($v, '([');
        if ($cut < strlen($v) && self::namesOnly(substr($v, 0, $cut))) {
            return true;
        }
        return strpos($v, '.') !== false && strpbrk($v, '0123456789') === false && self::namesOnly($v);
    }

    /**
     * Number of code points of a well-formed UTF-8 string. In: string. Out: int.
     * Why: CONVENTIONS (offsets and lengths are code points). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    private static function cpLen(string $s): int
    {
        return strlen($s) - (int)preg_match_all('#[\x80-\xBF]#', $s);
    }

    /**
     * Map byte offsets to code-point offsets in one walk. In: text, byte offsets. Out: [byte => code point].
     * Why: CONVENTIONS. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function byteToCp(string $text, array $offsets): array
    {
        $offsets = array_values(array_unique($offsets));
        sort($offsets);
        $map = [];
        $prevB = 0;
        $prevC = 0;
        $ascii = preg_match('#[\x80-\xFF]#', $text) !== 1;
        foreach ($offsets as $b) {
            if ($ascii) {
                $map[$b] = $b;
                continue;
            }
            $prevC += self::cpLen(substr($text, $prevB, $b - $prevB));
            $prevB = $b;
            $map[$b] = $prevC;
        }
        return $map;
    }

    /**
     * Map code-point offsets to byte offsets. In: text, code-point offsets. Out: [code point => byte].
     * Why: redact_text takes code-point findings. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static function cpToByte(string $text, array $offsets): array
    {
        $offsets = array_values(array_unique($offsets));
        sort($offsets);
        $map = [];
        $b = 0;
        $c = 0;
        $n = strlen($text);
        foreach ($offsets as $want) {
            while ($c < $want && $b < $n) {
                $b++;
                while ($b < $n && (ord($text[$b]) & 0xC0) === 0x80) {
                    $b++;
                }
                $c++;
            }
            $map[$want] = $b;
        }
        return $map;
    }

    /**
     * Turn kept candidates into findings: code-point start/end, preview = mask, value_hash = HMAC-SHA256 hex
     * (null without a key), encoded false. In: text, candidates. Out: [finding].
     * Why: SCREEN-11, SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private function toFindings(string $text, array $raw): array
    {
        $offs = [];
        foreach ($raw as $c) {
            $offs[] = $c['s'];
            $offs[] = $c['e'];
        }
        $map = self::byteToCp($text, $offs);
        $out = [];
        foreach ($raw as $c) {
            $value = substr($text, $c['s'], $c['e'] - $c['s']);
            $out[] = [
                'category' => $c['category'],
                'label' => $c['label'],
                'start' => $map[$c['s']],
                'end' => $map[$c['e']],
                'preview' => mask($value),
                'value_hash' => $this->hashKey === null ? null : hash_hmac('sha256', $value, $this->hashKey),
                'encoded' => false,
            ];
        }
        return $out;
    }

    /**
     * Replace byte spans by markers in one left-to-right pass. In: text, [{s, e, label}] sorted by s and
     * non-overlapping. Out: the new text. Why: SCREEN-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: nothing.
     */
    private static function redactRaw(string $text, array $raw): string
    {
        $parts = [];
        $at = 0;
        foreach ($raw as $c) {
            $parts[] = substr($text, $at, $c['s'] - $at);
            $parts[] = '[REDACTED:' . $c['label'] . ']';
            $at = $c['e'];
        }
        $parts[] = substr($text, $at);
        return implode('', $parts);
    }
}
