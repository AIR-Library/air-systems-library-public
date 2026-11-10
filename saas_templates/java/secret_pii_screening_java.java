import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Secret and PII screening (spec docs/specs/secret_pii_screening.md): finds secrets (API keys, tokens, private keys,
 * passwords in URLs and in assignments) and personal data (email addresses, phone numbers, card numbers, IP
 * addresses, US social security numbers) in a text before it is stored, logged or shared, and either refuses the
 * text (mode "reject", the default) or replaces every match with a [REDACTED:label] marker (mode "strip").
 *
 * In: texts to screen. Out: a {@link Result} (never an unhandled exception). Offsets count Unicode code points.
 * Why: Phase D wave 1, owner request 2026-11-10 (SCREEN-01 to SCREEN-14).
 * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
 * Touches: nothing outside memory: no database, no files, no network, no money. Never logs a text, a matched value
 * or the hash key.
 */
public final class SecretPiiScreening {

    /** Default max_bytes: 1 MiB of UTF-8. */
    public static final long DEFAULT_MAX_BYTES = 1048576L;

    /**
     * Construction failure (fail closed): a hash key shorter than 32 bytes. code is "invalid_hash_key".
     * SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static final class ScreenerConfigException extends RuntimeException {
        public final String code;

        /** In: the error code. Out: the exception (its message is the code, never the key). */
        public ScreenerConfigException(String code) {
            super(code);
            this.code = code;
        }
    }

    /**
     * One match. start/end are code points (end exclusive), -1/-1 when the match has no place in the text (found only
     * after redaction, or behind an escape). preview is mask(value); valueHash is HMAC-SHA256 hex or null.
     * Holds no matched value. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public record Finding(String category, String label, int start, int end, String preview, String valueHash,
                          boolean encoded) {
        /** Out: the finding as JSON text (for logs and results; it holds no matched value). */
        public String toJson() {
            return "{\"category\": " + q(category) + ", \"label\": " + q(label) + ", \"start\": " + start
                    + ", \"end\": " + end + ", \"preview\": " + q(preview) + ", \"value_hash\": "
                    + (valueHash == null ? "null" : q(valueHash)) + ", \"encoded\": " + encoded + "}";
        }

        /** Out: a copy with start/end -1 and encoded set as given. */
        Finding placeless(boolean enc) {
            return new Finding(category, label, -1, -1, preview, valueHash, enc);
        }
    }

    /**
     * The answer of screenText: ok + status 200 + text + findings, or a refusal ok=false with error and status (and the
     * findings for 422). A refusal never carries text. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static final class Result {
        public final boolean ok;
        public final String error;
        public final int status;
        public final String text;
        public final List<Finding> findings;

        Result(boolean ok, String error, int status, String text, List<Finding> findings) {
            this.ok = ok;
            this.error = error;
            this.status = status;
            this.text = text;
            this.findings = findings == null ? null : Collections.unmodifiableList(findings);
        }

        /** A refusal result. In: error code, HTTP status. Out: {ok: false, error, status}, no text. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
        static Result refuse(String error, int status) {
            return new Result(false, error, status, null, null);
        }

        /** Out: the whole result as JSON text (the shape a route serves). */
        public String toJson() {
            StringBuilder sb = new StringBuilder("{\"ok\": ").append(ok);
            if (error != null) sb.append(", \"error\": ").append(q(error));
            sb.append(", \"status\": ").append(status);
            if (text != null) sb.append(", \"text\": ").append(q(text));
            if (findings != null) {
                sb.append(", \"findings\": [");
                for (int i = 0; i < findings.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(findings.get(i).toJson());
                }
                sb.append("]");
            }
            return sb.append("}").toString();
        }

        @Override
        public String toString() {
            return toJson();
        }
    }

    /** resolve_escapes' answer: the decoded text and whether an escape is still left after 8 passes. */
    public record Resolved(String text, boolean unresolved) {}

    /** JSON string literal. In: text. Out: the quoted, escaped text. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String q(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') sb.append('\\').append(c);
            else if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
            else sb.append(c);
        }
        return sb.append('"').toString();
    }

    // ------------------------------------------------------------------------------------------------ detectors
    private static final String[] LABELS = {null,
        "pem_private_key", "pem_private_key", "openai_style_api_key", "stripe_style_api_key", "aws_access_key_id",
        "github_token", "slack_token", "google_api_key", "webhook_signing_secret", "jwt", "bearer_token",
        "url_credentials", "generic_key_value_assignment", "email_address", "phone_number", "credit_card_number",
        "ssn", "ip_address", "ip_address"};

    /** A detector's category. In: detector number. Out: "secret" (1-13) or "pii". Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String categoryOf(int det) {
        return det <= 13 ? "secret" : "pii";
    }

    private static final Pattern P_PEM = Pattern.compile(
        "-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----(?:\\r?\\nProc-Type: 4,ENCRYPTED\\r?\\nDEK-Info: "
        + "[A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\\r?\\n)?[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----");
    private static final Pattern P_PEM_HEADER = Pattern.compile("-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----");
    private static final Pattern P_OPENAI = Pattern.compile("sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]");
    private static final Pattern P_STRIPE = Pattern.compile("[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}");
    private static final Pattern P_AWS = Pattern.compile("A[KS]IA[0-9A-Z]{16}");
    private static final Pattern P_GITHUB = Pattern.compile("gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}");
    private static final Pattern P_SLACK = Pattern.compile("xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]");
    private static final Pattern P_GOOGLE = Pattern.compile("AIza[0-9A-Za-z_-]{35}");
    private static final Pattern P_WHSEC = Pattern.compile("whsec_[A-Za-z0-9+/=]{16,500}");
    private static final Pattern P_BEARER = Pattern.compile("[Bb][Ee][Aa][Rr][Ee][Rr][ \\t]+([A-Za-z0-9._~+/=-]{10,})");
    private static final Pattern P_URLCRED = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/ \\t\\r\\n:@]*:([^@ \\t\\r\\n/]+)@");
    private static final Pattern P_KV = Pattern.compile(
        "(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key"
        + "|credentials?|token)(?:\\\\?[\"'])?[ \\t]*(?::=|=>|[:=])[ \\t]*(?:\\\\?[\"'])?");
    private static final Pattern P_EMAIL = Pattern.compile("[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\\.){1,8}[A-Za-z]{2,24}");
    private static final Pattern P_PHONE = Pattern.compile(
        "(?:\\+?1[-. ]?)?\\(?[0-9]{3}\\)?[-. ][0-9]{3}[-. ][0-9]{4}|\\+[1-9][0-9]{7,14}");
    private static final Pattern P_CARD = Pattern.compile("[0-9](?:[ -]?[0-9]){12,18}");
    private static final Pattern P_SSN = Pattern.compile("[0-9]{3}-[0-9]{2}-[0-9]{4}");
    private static final Pattern P_IPV4 = Pattern.compile("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    private static final Pattern P_IPV6 = Pattern.compile("[0-9A-Fa-f:]{2,39}");
    private static final Pattern P_CARD_PREFIX = Pattern.compile(
        "^(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])"
        + "|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])");

    private static final Set<String> PLACEHOLDERS = new HashSet<>(Arrays.asList(
        "changeme", "change_me", "your_key_here", "your-key-here", "xxx", "xxxx", "xxxxx", "redacted", "todo",
        "example", "placeholder", "secret", "password", "insert_key_here", "none", "null", "n/a", "na",
        "<your-password>", "<your-key>", "fillmein"));

    private static final String REDACTED = "[REDACTED:";

    /** A candidate before combining: UTF-16 offsets into the text, and the detector number (its priority). */
    private record Cand(int start, int end, int det) {}

    private final byte[] hashKey;
    private final long maxBytes;

    /**
     * new_screener(hash_key = none, max_bytes = 1048576).
     * In: hashKey (null = no value_hash) and maxBytes. Out: a screener. Throws ScreenerConfigException
     * ("invalid_hash_key") for a key under 32 bytes, so no screener exists (fail closed, SCREEN-12).
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only (copies the key).
     */
    public SecretPiiScreening(byte[] hashKey, long maxBytes) {
        if (hashKey != null && hashKey.length < 32) {
            throw new ScreenerConfigException("invalid_hash_key");
        }
        this.hashKey = hashKey == null ? null : hashKey.clone();
        this.maxBytes = maxBytes;
    }

    /** new_screener with the default max_bytes. In: hashKey or null. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public SecretPiiScreening(byte[] hashKey) {
        this(hashKey, DEFAULT_MAX_BYTES);
    }

    /** new_screener with no hash key and the default max_bytes. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    public SecretPiiScreening() {
        this(null, DEFAULT_MAX_BYTES);
    }

    // ---------------------------------------------------------------------------------------------- entry point
    /** screen_text(text) in mode "reject" with both categories. See {@link #screenText(String, String, List)}. */
    public Result screenText(String text) {
        return screenText(text, "reject", List.of("secret", "pii"));
    }

    /** screen_text(text, mode) with both categories. See {@link #screenText(String, String, List)}. */
    public Result screenText(String text, String mode) {
        return screenText(text, mode, List.of("secret", "pii"));
    }

    /**
     * screen_text(text, mode, categories): the spec's steps 1-10 in order (invalid_text, invalid_mode,
     * invalid_categories, text_too_large, scan, reject, redact, strip re-scan, hidden check, ok).
     * In: the text, "reject" | "strip", a non-empty list of "secret" / "pii". Out: a Result; anything raised while
     * scanning (a stack overflow included) is 500 screening_failed (fail closed). Why: SCREEN-01..14.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public Result screenText(String text, String mode, List<String> categories) {
        if (text == null || !wellFormed(text)) return Result.refuse("invalid_text", 400);
        if (!"reject".equals(mode) && !"strip".equals(mode)) return Result.refuse("invalid_mode", 400);
        if (categories == null || categories.isEmpty()) return Result.refuse("invalid_categories", 400);
        for (String c : categories) {
            if (!"secret".equals(c) && !"pii".equals(c)) return Result.refuse("invalid_categories", 400);
        }
        if (utf8Length(text) > maxBytes) return Result.refuse("text_too_large", 413);
        try {
            List<Finding> f = scanText(text, categories);
            if ("reject".equals(mode) && !f.isEmpty()) {
                return new Result(false, "secrets_or_pii_detected", 422, null, f);
            }
            String out = f.isEmpty() ? text : redactText(text, f);
            if ("strip".equals(mode) && !f.isEmpty()) {
                List<Finding> f2 = scanText(out, categories);
                if (!f2.isEmpty()) {
                    List<Finding> all = new ArrayList<>(f);
                    for (Finding x : f2) all.add(x.placeless(false));
                    return new Result(false, "secrets_or_pii_detected", 422, null, all);
                }
            }
            if (out.indexOf('\\') >= 0) {
                Resolved r = resolveEscapes(out);
                List<Finding> h = new ArrayList<>();
                if (!r.text().equals(out)) {
                    for (Finding x : scanText(r.text(), categories)) h.add(x.placeless(true));
                }
                if (r.unresolved()) {
                    h.add(new Finding("secret", "unresolved_escape", -1, -1, "***", null, true));
                }
                if (!h.isEmpty()) {
                    List<Finding> all = new ArrayList<>(f);
                    all.addAll(h);
                    return new Result(false, "secrets_or_pii_detected", 422, null, all);
                }
            }
            return new Result(true, null, 200, out, f);
        } catch (RuntimeException | StackOverflowError e) {
            return Result.refuse("screening_failed", 500);
        }
    }

    // ---------------------------------------------------------------------------------------------- scan
    /** scan_text(text) with both categories. */
    public List<Finding> scanText(String text) {
        return scanText(text, List.of("secret", "pii"));
    }

    /**
     * scan_text(text, categories): runs every detector of the given categories, combines the candidates (earliest
     * start, then longest span in code points, then lowest detector number; no character in two findings) and returns
     * the findings ordered by start, with code-point offsets, mask previews and keyed hashes.
     * In: text, categories. Out: the findings. Why: SCREEN-02..08, SCREEN-11. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public List<Finding> scanText(String text, List<String> categories) {
        boolean secrets = categories.contains("secret");
        boolean pii = categories.contains("pii");
        List<Cand> c = new ArrayList<>();
        if (secrets) {
            regexDetector(1, P_PEM, text, text, c);
            pemTruncated(text, c);
            regexDetector(3, P_OPENAI, text, text, c);
            regexDetector(4, P_STRIPE, text, text, c);
            regexDetector(5, P_AWS, text, text, c);
            regexDetector(6, P_GITHUB, text, text, c);
            regexDetector(7, P_SLACK, text, text, c);
            regexDetector(8, P_GOOGLE, text, text, c);
            regexDetector(9, P_WHSEC, text, text, c);
            jwt(text, c);
            regexDetector(11, P_BEARER, text, text, c);
            regexDetector(12, P_URLCRED, text, text, c);
            keyValue(text, c);
        }
        if (pii) {
            regexDetector(14, P_EMAIL, text, text, c);
            regexDetector(15, P_PHONE, text, text, c);
            regexDetector(16, P_CARD, text, text, c);
            regexDetector(17, P_SSN, text, text, c);
            regexDetector(18, P_IPV4, text, text, c);
            regexDetector(19, P_IPV6, text, text, c);
        }
        int[] cp = codePointIndex(text);
        c.sort((a, b) -> {
            int sa = cpAt(cp, a.start), sb = cpAt(cp, b.start);
            if (sa != sb) return Integer.compare(sa, sb);
            int la = cpAt(cp, a.end) - sa, lb = cpAt(cp, b.end) - sb;
            if (la != lb) return Integer.compare(lb, la);
            return Integer.compare(a.det, b.det);
        });
        List<Finding> out = new ArrayList<>();
        int lastEnd = -1;
        for (Cand x : c) {
            int s = cpAt(cp, x.start), e = cpAt(cp, x.end);
            if (s >= lastEnd) {
                String value = text.substring(x.start, x.end);
                out.add(new Finding(categoryOf(x.det), LABELS[x.det], s, e, mask(value), valueHash(value), false));
                lastEnd = e;
            }
        }
        return out;
    }

    /** null when the text holds no surrogate (UTF-16 index = code point index), else the map UTF-16 -> code point. */
    private static int[] codePointIndex(String text) {
        boolean any = false;
        for (int i = 0; i < text.length(); i++) {
            if (Character.isSurrogate(text.charAt(i))) {
                any = true;
                break;
            }
        }
        if (!any) return null;
        int[] m = new int[text.length() + 1];
        int cp = 0;
        for (int i = 0; i < text.length(); i++) {
            m[i] = cp;
            if (Character.isHighSurrogate(text.charAt(i)) && i + 1 < text.length()
                    && Character.isLowSurrogate(text.charAt(i + 1))) {
                m[++i] = cp;
            }
            cp++;
        }
        m[text.length()] = cp;
        return m;
    }

    /** A UTF-16 index as a code point index. In: the map (null = identity), index. Out: code points. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static int cpAt(int[] map, int i) {
        return map == null ? i : map[i];
    }

    /** W = [A-Za-z0-9_]. In: a character (-1 = none). Out: membership. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isW(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    }

    /** An ASCII digit 0-9 only. In: a character. Out: true/false. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isDigit(int c) {
        return c >= '0' && c <= '9';
    }

    /** In: text. Out: true when it holds an ASCII digit 0-9. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean hasDigit(CharSequence s) {
        for (int i = 0; i < s.length(); i++) if (isDigit(s.charAt(i))) return true;
        return false;
    }

    /** In: text. Out: the places where a-z is directly followed by A-Z. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static int humps(CharSequence s) {
        int n = 0;
        for (int i = 0; i + 1 < s.length(); i++) {
            char a = s.charAt(i), b = s.charAt(i + 1);
            if (a >= 'a' && a <= 'z' && b >= 'A' && b <= 'Z') n++;
        }
        return n;
    }

    /**
     * find_all for a regex detector: leftmost match at or after pos; accepted -> candidate, pos = end of m (end of the
     * card prefix for detector 16); refused -> pos = start of m + 1. In: detector number, pattern, the text the
     * pattern runs on, the original text, the candidate list (appended). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    private static void regexDetector(int det, Pattern p, String hay, String text, List<Cand> out) {
        Matcher m = p.matcher(hay);
        int n = hay.length();
        int pos = 0;
        while (pos <= n && m.find(pos)) {
            int s = m.start(), e = m.end();
            int before = s > 0 ? hay.charAt(s - 1) : -1;
            int after = e < n ? hay.charAt(e) : -1;
            int cs = s, ce = e, next = e;
            boolean ok;
            switch (det) {
                case 1 -> ok = true;
                case 3 -> ok = !isW(before) && hasDigit(hay.substring(s, e));
                case 4, 5, 6, 7 -> ok = !isW(before) && !isW(after);
                case 8 -> ok = !isW(before) && !isW(after) && after != '-';
                case 9 -> ok = !isW(before);
                case 11 -> {
                    String g = m.group(1);
                    ok = !isW(before) && (hasDigit(g) || humps(g) >= 2);
                    cs = m.start(1);
                    ce = m.end(1);
                }
                case 12 -> {
                    String g = m.group(1);
                    ok = !g.startsWith(REDACTED) && !PLACEHOLDERS.contains(asciiLower(g));
                    cs = m.start(1);
                    ce = m.end(1);
                }
                case 14 -> ok = !isW(before) && !isW(after) && !inUrlUserPart(hay, s);
                case 15 -> ok = !isDigit(before) && !isDigit(after);
                case 16 -> {
                    int end = isW(before) ? -1 : cardPrefixEnd(hay, s, e);
                    ok = end > 0;
                    ce = end;
                    next = end;
                }
                case 17 -> ok = !isW(before) && before != '-' && !isW(after) && after != '-' && ssnCheck(hay.substring(s, e));
                case 18 -> ok = !isW(before) && before != '.' && !isW(after)
                        && !(after == '.' && e + 1 < n && isDigit(hay.charAt(e + 1))) && ipv4Check(hay.substring(s, e));
                case 19 -> ok = !(isW(before) || before == ':' || before == '.') && !(isW(after) || after == ':')
                        && ipv6Check(hay.substring(s, e));
                default -> throw new IllegalStateException("unknown detector");
            }
            if (ok) {
                out.add(new Cand(cs, ce, det));
                pos = next;
            } else {
                pos = s + 1;
            }
        }
    }

    /** Email guard: true when the match is the user part of a URL (the nearest / @ space tab CR LF before it ends "://"). */
    private static boolean inUrlUserPart(String t, int s) {
        int k = s - 1;
        while (k >= 0) {
            char c = t.charAt(k);
            if (c == '/' || c == '@' || c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
            k--;
        }
        return k >= 2 && t.charAt(k - 2) == ':' && t.charAt(k - 1) == '/' && t.charAt(k) == '/';
    }

    /**
     * Detector 16's span: the end (exclusive, UTF-16) of the LONGEST prefix of m that holds 13-19 digits, ends at the
     * end of m with after not W or just before a space or "-" inside m, is grouped like a card, starts with a card
     * network prefix and passes Luhn. -1 when there is none.
     */
    private static int cardPrefixEnd(String t, int s, int e) {
        StringBuilder digits = new StringBuilder();
        for (int i = s; i < e; i++) if (isDigit(t.charAt(i))) digits.append(t.charAt(i));
        if (!P_CARD_PREFIX.matcher(digits).find()) return -1;
        int after = e < t.length() ? t.charAt(e) : -1;
        for (int end = e; end > s; end--) {
            boolean boundary = end == e ? !isW(after) : (t.charAt(end) == ' ' || t.charAt(end) == '-');
            if (!boundary) continue;
            String p = t.substring(s, end);
            String d = p.replace(" ", "").replace("-", "");
            if (d.length() < 13 || d.length() > 19) continue;
            String[] groups = p.split("[ -]", -1);
            boolean grouped = true;
            for (int g = 0; g < groups.length - 1; g++) {
                if (groups[g].length() < 4) {
                    grouped = false;
                    break;
                }
            }
            if (grouped && luhn(d)) return end;
        }
        return -1;
    }

    /** Luhn check. In: digits. Out: true when the sum is a multiple of 10. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean luhn(String d) {
        int sum = 0;
        boolean dbl = false;
        for (int i = d.length() - 1; i >= 0; i--) {
            int v = d.charAt(i) - '0';
            if (dbl) {
                v *= 2;
                if (v > 9) v -= 9;
            }
            sum += v;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    /** Detector 17's check. In: NNN-NN-NNNN. Out: false for area 000, 666, 9xx, group 00, serial 0000. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean ssnCheck(String m) {
        String a = m.substring(0, 3), b = m.substring(4, 6), c = m.substring(7);
        return !a.equals("000") && !a.equals("666") && a.charAt(0) != '9' && !b.equals("00") && !c.equals("0000");
    }

    /** Detector 18's check. In: a dotted quad. Out: true for a public host address. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean ipv4Check(String m) {
        String[] parts = m.split("\\.", -1);
        int[] v = new int[4];
        for (int i = 0; i < 4; i++) {
            if (parts[i].length() > 1 && parts[i].charAt(0) == '0') return false;
            v[i] = Integer.parseInt(parts[i]);
            if (v[i] > 255) return false;
        }
        if (v[0] == 0 || v[0] == 10 || v[0] == 127 || v[0] >= 224) return false;
        if (v[0] == 169 && v[1] == 254) return false;
        if (v[0] == 172 && v[1] >= 16 && v[1] <= 31) return false;
        if (v[0] == 192 && v[1] == 168) return false;
        return v[3] != 0;
    }

    /** In: an IPv6 group. Out: true for 1 to 4 hex digits. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean hexGroup(String g) {
        if (g.isEmpty() || g.length() > 4) return false;
        for (int i = 0; i < g.length(); i++) {
            char c = g.charAt(i);
            if (!(isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        }
        return true;
    }

    /** Detector 19's check. In: the match. Out: true for a well-formed global (2000::/3) address. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean ipv6Check(String m) {
        if (m.contains(":::")) return false;
        int dc = m.indexOf("::");
        if (dc >= 0 && m.indexOf("::", dc + 1) >= 0) return false;
        int first;
        if (dc >= 0) {
            String left = m.substring(0, dc), right = m.substring(dc + 2);
            String[] lg = left.isEmpty() ? new String[0] : left.split(":", -1);
            String[] rg = right.isEmpty() ? new String[0] : right.split(":", -1);
            if (lg.length + rg.length > 7) return false;
            for (String g : lg) if (!hexGroup(g)) return false;
            for (String g : rg) if (!hexGroup(g)) return false;
            first = lg.length == 0 ? 0 : Integer.parseInt(lg[0], 16);
        } else {
            String[] g = m.split(":", -1);
            if (g.length != 8) return false;
            for (String x : g) if (!hexGroup(x)) return false;
            first = Integer.parseInt(g[0], 16);
        }
        return first >= 0x2000 && first <= 0x3fff;
    }

    /**
     * Detector 2: a private key block cut off before its END line, found by hand (no repeated group: java.util.regex
     * would overflow its stack). Counts only the characters of base64 runs of at least 16; 60 or more is a candidate.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    private static void pemTruncated(String t, List<Cand> out) {
        Matcher h = P_PEM_HEADER.matcher(t);
        int n = t.length();
        int pos = 0;
        while (pos <= n && h.find(pos)) {
            int p = h.end(), count = 0, end = -1;
            while (true) {
                int q = p;
                while (q < n) {
                    char c = t.charAt(q);
                    if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '>' || c == '-') {
                        q++;
                    } else if (c == '\\' && q + 1 < n && t.charAt(q + 1) == 'n') {
                        q += 2;
                    } else if (c == '\\' && q + 3 < n && t.charAt(q + 1) == 'r' && t.charAt(q + 2) == '\\' && t.charAt(q + 3) == 'n') {
                        q += 4;
                    } else {
                        break;
                    }
                }
                int r = q;
                while (r < n && isB64(t.charAt(r))) r++;
                if (r - q < 16) break;
                count += r - q;
                end = r;
                p = r;
            }
            if (count >= 60) {
                out.add(new Cand(h.start(), end, 2));
                pos = end;
            } else {
                pos = h.start() + 1;
            }
        }
    }

    /** In: a character. Out: true for [A-Za-z0-9+/=] (detector 2's runs). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isB64(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isDigit(c) || c == '+' || c == '/' || c == '=';
    }

    /** In: a character. Out: true for S = [A-Za-z0-9_-] (detector 10). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isS(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isDigit(c) || c == '_' || c == '-';
    }

    /**
     * Detector 10: a JWT found by hand (linear for any input): "eyJ" not after a W character, a run of at least 8 S
     * characters, ".", a run of at least 5, ".", a run of at least 5. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
     * Touches: memory only.
     */
    private static void jwt(String t, List<Cand> out) {
        int n = t.length();
        int pos = 0;
        while (true) {
            int i = t.indexOf("eyJ", pos);
            if (i < 0) return;
            if (i > 0 && isW(t.charAt(i - 1))) {
                pos = i + 1;
                continue;
            }
            int j = i;
            while (j < n && isS(t.charAt(j))) j++;
            pos = j;
            if (j - i >= 8 && j < n && t.charAt(j) == '.') {
                int a = j + 1, b = a;
                while (b < n && isS(t.charAt(b))) b++;
                if (b - a >= 5 && b < n && t.charAt(b) == '.') {
                    int c = b + 1, e = c;
                    while (e < n && isS(t.charAt(e))) e++;
                    if (e - c >= 5) {
                        out.add(new Cand(i, e, 10));
                        pos = e;
                    }
                }
            }
        }
    }

    /** In: a character. Out: true for what ends a detector-13 value (space, tab, LF, CR, FF, VT, quotes). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean isValueStop(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\u000B' || c == '\'' || c == '"';
    }

    /**
     * Detector 13: key = value assignments. The regex runs on the ASCII lower case of the text; the value is taken
     * from the original text. Checks in the spec's order: "[REDACTED:" first, then 8 code points, then (without the
     * sentence's closing punctuation) placeholder, reference and looks_like_secret. Changed 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (spec ruling fed6e7b): where each value ends, the next "(" or "[" and the next
     * digit come from lookup tables built once per text, the checks work on positions (no copy of the value), and
     * the instant refusals run first, so "token=$" * 28571 is linear; the answers are unchanged.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    private static void keyValue(String t, List<Cand> out) {
        String lower = asciiLower(t);
        Matcher m = P_KV.matcher(lower);
        int n = t.length();
        int pos = 0;
        int[] valueEnd = null, nextParen = null, nextDigit = null;
        int lastVe = -1, lastVEnd = -1;
        while (pos <= n && m.find(pos)) {
            int s = m.start(), e = m.end();
            int run = 0, k = s - 1;
            while (k >= 0 && run <= 40) {
                char c = lower.charAt(k);
                if ((c >= 'a' && c <= 'z') || isDigit(c) || c == '_' || c == '.' || c == '-') {
                    run++;
                    k--;
                } else {
                    break;
                }
            }
            if (run > 40 || t.startsWith(REDACTED, e)) {
                pos = s + 1;
                continue;
            }
            if (valueEnd == null) {
                // The lookup tables, built once per text (fed6e7b: detector 13 must stay linear).
                valueEnd = new int[n + 1];
                nextParen = new int[n + 1];
                nextDigit = new int[n + 1];
                valueEnd[n] = n;
                nextParen[n] = n;
                nextDigit[n] = n;
                for (int i = n - 1; i >= 0; i--) {
                    char c = t.charAt(i);
                    boolean stop = isValueStop(c) || c == ';' || (c == '\\' && i + 1 < n && isValueStop(t.charAt(i + 1)));
                    valueEnd[i] = stop ? i : valueEnd[i + 1];
                    nextParen[i] = (c == '(' || c == '[') ? i : nextParen[i + 1];
                    nextDigit[i] = isDigit(c) ? i : nextDigit[i + 1];
                }
            }
            int ve = valueEnd[e];
            if (atLeastCodePoints(t, e, ve, 8)) {
                int vEnd;
                if (ve == lastVe) {
                    vEnd = Math.max(lastVEnd, e);
                } else {
                    vEnd = ve;
                    while (vEnd > e && ".,;:!?".indexOf(t.charAt(vEnd - 1)) >= 0) vEnd--;
                    lastVe = ve;
                    lastVEnd = vEnd;
                }
                // The instant refusals first (a reference's first character, a short placeholder); every check is a
                // refusal, so their order changes only the time, never the answer.
                if (!isReferenceAt(t, e, vEnd, nextParen, nextDigit)
                        && !(vEnd - e <= 20 && PLACEHOLDERS.contains(asciiLower(t.substring(e, vEnd))))
                        && looksLikeSecretAt(t, e, vEnd)) {
                    out.add(new Cand(e, ve, 13));
                    pos = ve;
                    continue;
                }
            }
            pos = s + 1;
        }
    }

    /** In: text, range, minimum. Out: true when the range holds at least min code points (counts no further). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean atLeastCodePoints(String t, int from, int to, int min) {
        int count = 0;
        int i = from;
        while (i < to && count < min) {
            i += Character.isHighSurrogate(t.charAt(i)) && i + 1 < to && Character.isLowSurrogate(t.charAt(i + 1)) ? 2 : 1;
            count++;
        }
        return count >= min;
    }

    /** looks_like_secret(v) on the whole text. See {@link #looksLikeSecretAt}. */
    static boolean looksLikeSecret(String v) {
        return looksLikeSecretAt(v, 0, v.length());
    }

    /**
     * looks_like_secret(V) for V = t[a, b): a digit 0-9; or a character below U+0080 outside [A-Za-z0-9]; or at least
     * 2 places where a-z is directly followed by A-Z. Stops at the first proof. Phase D wave 1, 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static boolean looksLikeSecretAt(String t, int a, int b) {
        int humps = 0;
        for (int i = a; i < b; i++) {
            char c = t.charAt(i);
            if (isDigit(c)) return true;
            if (c < 0x80 && !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return true;
            if (i + 1 < b && c >= 'a' && c <= 'z' && t.charAt(i + 1) >= 'A' && t.charAt(i + 1) <= 'Z' && ++humps >= 2) return true;
        }
        return false;
    }

    /** In: a character. Out: true for a NAME's first character [A-Za-z_]. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean nameStart(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
    }

    /**
     * True when t[a, b), split at ".", is NAMEs only (each part a letter or "_" then letters, digits and "_"); when
     * needDot is set, it must also hold a ".". Stops at the first character that breaks the rule. Phase D wave 1,
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    private static boolean dottedNames(String t, int a, int b, boolean needDot) {
        int i = a;
        boolean dot = false;
        while (true) {
            if (i >= b || !nameStart(t.charAt(i))) return false;
            i++;
            while (i < b && isW(t.charAt(i))) i++;
            if (i == b) return dot || !needDot;
            if (t.charAt(i) != '.') return false;
            dot = true;
            i++;
        }
    }

    /** REFERENCE(V) on the whole text. See {@link #isReferenceAt}. */
    static boolean isReference(String v) {
        int n = v.length();
        int[] paren = new int[n + 1], digit = new int[n + 1];
        paren[n] = n;
        digit[n] = n;
        for (int i = n - 1; i >= 0; i--) {
            char c = v.charAt(i);
            paren[i] = (c == '(' || c == '[') ? i : paren[i + 1];
            digit[i] = isDigit(c) ? i : digit[i + 1];
        }
        return isReferenceAt(v, 0, n, paren, digit);
    }

    /**
     * REFERENCE(V) for V = t[a, b): it starts with $ < { % *; or before its first "(" or "[" it is dotted NAMEs only;
     * or it holds a ".", no digit 0-9, and is dotted NAMEs only. nextParen and nextDigit are the text's lookup
     * tables (the next "(" or "[" and the next digit at or after each position). Phase D wave 1, 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP (tables: spec ruling fed6e7b). Touches: nothing.
     */
    private static boolean isReferenceAt(String t, int a, int b, int[] nextParen, int[] nextDigit) {
        if (a >= b) return false;
        char c0 = t.charAt(a);
        if (c0 == '$' || c0 == '<' || c0 == '{' || c0 == '%' || c0 == '*') return true;
        int paren = nextParen[a];
        if (paren < b && dottedNames(t, a, paren, false)) return true;
        return nextDigit[a] >= b && dottedNames(t, a, b, true);
    }

    // ---------------------------------------------------------------------------------------------- helpers
    /** ASCII lower case: A-Z to a-z only, every other character unchanged (positions stay the same). */
    static String asciiLower(String s) {
        char[] a = s.toCharArray();
        for (int i = 0; i < a.length; i++) if (a[i] >= 'A' && a[i] <= 'Z') a[i] = (char) (a[i] + 32);
        return new String(a);
    }

    /**
     * mask(value): fewer than 16 code points -> that many "*"; otherwise the first 2 characters, n - 4 "*", the last 2.
     * SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: nothing.
     */
    public static String mask(String value) {
        int[] cps = value.codePoints().toArray();
        int n = cps.length;
        if (n < 16) return "*".repeat(n);
        StringBuilder sb = new StringBuilder();
        sb.appendCodePoint(cps[0]).appendCodePoint(cps[1]);
        sb.append("*".repeat(n - 4));
        sb.appendCodePoint(cps[n - 2]).appendCodePoint(cps[n - 1]);
        return sb.toString();
    }

    /** value_hash: lower-case hex HMAC-SHA256(hash_key, UTF-8 of value), or null without a key. */
    private String valueHash(String value) {
        if (hashKey == null) return null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hashKey, "HmacSHA256"));
            byte[] d = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("hmac unavailable");
        }
    }

    /**
     * redact_text(text, findings): each finding's span (code points) replaced by "[REDACTED:" + label + "]", built in
     * one left-to-right pass. Findings without a place (start -1) are skipped. 2026-11-10,
     * session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public static String redactText(String text, List<Finding> findings) {
        List<Finding> fs = new ArrayList<>();
        for (Finding f : findings) if (f.start() >= 0) fs.add(f);
        fs.sort((a, b) -> Integer.compare(a.start(), b.start()));
        StringBuilder sb = new StringBuilder(text.length());
        int fi = 0, cp = 0, i = 0, n = text.length();
        while (i < n) {
            if (fi < fs.size() && cp == fs.get(fi).start()) {
                Finding f = fs.get(fi++);
                sb.append(REDACTED).append(f.label()).append(']');
                while (i < n && cp < f.end()) {
                    i += Character.charCount(text.codePointAt(i));
                    cp++;
                }
                continue;
            }
            int c = text.codePointAt(i);
            sb.appendCodePoint(c);
            i += Character.charCount(c);
            cp++;
        }
        return sb.toString();
    }

    /** In: a character. Out: its hex value, or -1. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static int hexVal(char c) {
        if (isDigit(c)) return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** -1 when there is no \\uXXXX escape at i, else its 16-bit value. */
    private static int uEscape(String t, int i) {
        if (i + 6 > t.length() || t.charAt(i) != '\\' || t.charAt(i + 1) != 'u') return -1;
        int v = 0;
        for (int k = 2; k < 6; k++) {
            int h = hexVal(t.charAt(i + k));
            if (h < 0) return -1;
            v = v * 16 + h;
        }
        return v;
    }

    /** In: text. Out: true when it holds an ESCAPE (\\uXXXX or a backslash and one of " \\ / b f n r t). Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static boolean holdsEscape(String t) {
        for (int i = 0; i + 1 < t.length(); i++) {
            if (t.charAt(i) != '\\') continue;
            if ("\"\\/bfnrt".indexOf(t.charAt(i + 1)) >= 0 || uEscape(t, i) >= 0) return true;
        }
        return false;
    }

    /** One left-to-right pass of ESCAPE decoding (pairs surrogates, lone ones become U+FFFD). In: text. Out: decoded text. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static String escapePass(String t) {
        StringBuilder sb = new StringBuilder(t.length());
        int i = 0, n = t.length();
        while (i < n) {
            char c = t.charAt(i);
            if (c != '\\' || i + 1 >= n) {
                sb.append(c);
                i++;
                continue;
            }
            int u = uEscape(t, i);
            if (u >= 0) {
                if (u >= 0xD800 && u <= 0xDBFF) {
                    int lo = uEscape(t, i + 6);
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        sb.appendCodePoint(Character.toCodePoint((char) u, (char) lo));
                        i += 12;
                        continue;
                    }
                    sb.append('\uFFFD');
                } else if (u >= 0xDC00 && u <= 0xDFFF) {
                    sb.append('\uFFFD');
                } else {
                    sb.append((char) u);
                }
                i += 6;
                continue;
            }
            char d = t.charAt(i + 1);
            switch (d) {
                case '"' -> sb.append('"');
                case '\\' -> sb.append('\\');
                case '/' -> sb.append('/');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                default -> {
                    sb.append(c);
                    i++;
                    continue;
                }
            }
            i += 2;
        }
        return sb.toString();
    }

    /**
     * resolve_escapes(text): repeats one left-to-right pass of JSON escape decoding while the text holds an escape, at
     * most 8 times; unresolved = an escape is still left after the 8th pass. SCREEN-13.
     * 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: memory only.
     */
    public static Resolved resolveEscapes(String text) {
        String t = text;
        for (int pass = 0; pass < 8 && holdsEscape(t); pass++) t = escapePass(t);
        return new Resolved(t, holdsEscape(t));
    }

    /** True when every surrogate is paired (well-formed UTF-16). */
    private static boolean wellFormed(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) return false;
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }

    /** In: well-formed text. Out: its UTF-8 length in bytes, without encoding it. Touches: nothing. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. */
    private static long utf8Length(String s) {
        long n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80) n += 1;
            else if (c < 0x800) n += 2;
            else if (Character.isHighSurrogate(c)) {
                n += 4;
                i++;
            } else n += 3;
        }
        return n;
    }
}
