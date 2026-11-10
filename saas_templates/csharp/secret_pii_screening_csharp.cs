// Secret & PII screening template (docs/specs/secret_pii_screening.md): finds secrets (API keys, tokens, private
// keys, passwords in URLs and in assignments) and personal data (email addresses, phone numbers, card numbers, IP
// addresses, US social security numbers) in a text BEFORE it is stored, logged or shared, and either refuses the text
// (reject, the default) or replaces each match with a [REDACTED:label] marker (strip). Nineteen detectors, combined so
// no character is in two findings; offsets in Unicode code points; a hidden check for secrets behind JSON escapes.
// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10).
// Touches nothing: it stores nothing, logs nothing, and has no network. Never logs the text, a matched value or the
// hash key.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AOI.SecretPiiScreening
{
    /// <summary>
    /// Construction refused (fail closed): a hash_key under 32 bytes (Code "invalid_hash_key"). Why: SCREEN-12.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
    /// </summary>
    public sealed class ScreenerConfigException : Exception
    {
        /// <summary>The spec's error code. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public string Code { get; }

        /// <summary>Creates the exception; the message never holds the key. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public ScreenerConfigException(string code) : base(code) { Code = code; }
    }

    /// <summary>
    /// One finding: category, label, start and end (code points, end exclusive; -1 for a hidden one), the masked preview,
    /// the keyed hash (or null) and whether it was found behind escapes. It never holds the matched value. Pure data.
    /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class Finding
    {
        public string Category { get; set; }
        public string Label { get; set; }
        public long Start { get; set; }
        public long End { get; set; }
        public string Preview { get; set; }
        public string ValueHash { get; set; }
        public bool Encoded { get; set; }

        /// <summary>The same finding moved out of the text (start and end -1), optionally marked encoded. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public Finding Hidden(bool encoded) => new Finding { Category = Category, Label = Label, Start = -1, End = -1, Preview = Preview, ValueHash = ValueHash, Encoded = encoded };
    }

    /// <summary>
    /// screen_text's answer: {ok: true, status: 200, text, findings} or {ok: false, error, status} (with findings for a
    /// 422). A refusal never carries the text. Pure data. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
    /// </summary>
    public sealed class ScreenResult
    {
        public bool Ok { get; set; }
        public int Status { get; set; }
        public string Error { get; set; }
        public string Text { get; set; }
        public List<Finding> Findings { get; set; } = new List<Finding>();

        /// <summary>A refusal without findings. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static ScreenResult Fail(int status, string error) => new ScreenResult { Ok = false, Status = status, Error = error };
    }

    /// <summary>resolve_escapes' answer: the text after at most 8 passes, and whether an escape is still in it. Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
    public sealed class EscapeResolution
    {
        public string Text { get; set; }
        public bool Unresolved { get; set; }
    }

    /// <summary>
    /// The screener: screen_text, scan_text, redact_text, mask and resolve_escapes, with the spec's nineteen detectors.
    /// Written 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (Phase D wave 1, owner request 2026-11-10). Touches nothing.
    /// </summary>
    public sealed class Screener
    {
        /// <summary>A candidate in UTF-16 units [Start, End), with its detector number. Pure data. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private readonly struct Candidate
        {
            public readonly int Start, End, Detector;
            /// <summary>A candidate span and its detector. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
            public Candidate(int start, int end, int detector) { Start = start; End = end; Detector = detector; }
        }

        private const RegexOptions Opts = RegexOptions.CultureInvariant;
        private static readonly Regex PemFull = new Regex(@"-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----(?:\r?\nProc-Type: 4,ENCRYPTED\r?\nDEK-Info: [A-Z0-9-]{1,32},[0-9A-Fa-f]{1,64}\r?\n)?[^-]*-----END (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----", Opts);
        private static readonly Regex PemHeader = new Regex(@"-----BEGIN (?:[A-Z0-9]+ ){0,8}PRIVATE KEY(?: BLOCK)?-----", Opts);
        private static readonly Regex OpenAi = new Regex(@"sk-[A-Za-z0-9_-]{15,499}[A-Za-z0-9_]", Opts);
        private static readonly Regex StripeKey = new Regex(@"[spr]k_(?:live|test)_[A-Za-z0-9]{16,500}", Opts);
        private static readonly Regex Aws = new Regex(@"A[KS]IA[0-9A-Z]{16}", Opts);
        private static readonly Regex GitHub = new Regex(@"gh[pousr]_[A-Za-z0-9]{20,500}|github_pat_[A-Za-z0-9_]{20,500}", Opts);
        private static readonly Regex Slack = new Regex(@"xox[abprs]-[A-Za-z0-9-]{9,499}[A-Za-z0-9]", Opts);
        private static readonly Regex Google = new Regex(@"AIza[0-9A-Za-z_-]{35}", Opts);
        private static readonly Regex Whsec = new Regex(@"whsec_[A-Za-z0-9+/=]{16,500}", Opts);
        private static readonly Regex Bearer = new Regex(@"[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+([A-Za-z0-9._~+/=-]{10,})", Opts);
        private static readonly Regex UrlCred = new Regex(@"[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/ \t\r\n:@]*:([^@ \t\r\n/]+)@", Opts);
        private static readonly Regex KeyValue = new Regex(@"(?:api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?key|auth[_-]?token|private[_-]?key|credentials?|token)(?:\\?[""'])?[ \t]*(?::=|=>|[:=])[ \t]*(?:\\?[""'])?", Opts);
        private static readonly Regex Email = new Regex(@"[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}", Opts);
        private static readonly Regex Phone = new Regex(@"(?:\+?1[-. ]?)?\(?[0-9]{3}\)?[-. ][0-9]{3}[-. ][0-9]{4}|\+[1-9][0-9]{7,14}", Opts);
        private static readonly Regex Card = new Regex(@"[0-9](?:[ -]?[0-9]){12,18}", Opts);
        private static readonly Regex Ssn = new Regex(@"[0-9]{3}-[0-9]{2}-[0-9]{4}", Opts);
        private static readonly Regex Ipv4 = new Regex(@"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", Opts);
        private static readonly Regex Ipv6 = new Regex(@"[0-9A-Fa-f:]{2,39}", Opts);
        private static readonly Regex CardPrefix = new Regex(@"^(?:4|5[1-5]|2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9][0-9]|7[01][0-9]|720)|3[47]|6(?:011|5[0-9][0-9]|4[4-9][0-9])|3(?:0[0-5]|[68][0-9])|35[0-9][0-9])", Opts);

        private static readonly string[] Labels =
        {
            null, "pem_private_key", "pem_private_key", "openai_style_api_key", "stripe_style_api_key", "aws_access_key_id",
            "github_token", "slack_token", "google_api_key", "webhook_signing_secret", "jwt", "bearer_token", "url_credentials",
            "generic_key_value_assignment", "email_address", "phone_number", "credit_card_number", "ssn", "ip_address", "ip_address",
        };

        private static readonly HashSet<string> Placeholders = new HashSet<string>(StringComparer.Ordinal)
        {
            "changeme", "change_me", "your_key_here", "your-key-here", "xxx", "xxxx", "xxxxx", "redacted", "todo", "example",
            "placeholder", "secret", "password", "insert_key_here", "none", "null", "n/a", "na", "<your-password>", "<your-key>", "fillmein",
        };

        private readonly byte[] _hashKey;
        private readonly long _maxBytes;

        /// <summary>
        /// new_screener: In: hash_key (null: every value_hash is null; under 32 bytes: ScreenerConfigException
        /// "invalid_hash_key", fail closed) and max_bytes. Why: SCREEN-12/14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// Touches nothing.
        /// </summary>
        public Screener(byte[] hashKey = null, long maxBytes = 1048576)
        {
            if (hashKey != null && hashKey.Length < 32) throw new ScreenerConfigException("invalid_hash_key");
            _hashKey = hashKey == null ? null : (byte[])hashKey.Clone();
            _maxBytes = maxBytes;
        }

        // ------------------------------------------------------------------ public functions

        /// <summary>
        /// screen_text: invalid_text (400), invalid_mode (400), invalid_categories (400), text_too_large (413), all before
        /// any scan; then scan; reject with findings is 422 secrets_or_pii_detected; strip redacts and screens its output
        /// again (a new match is 422); a text with a backslash gets the hidden check (a secret behind escapes is 422 in
        /// both modes). Anything raised inside is 500 screening_failed. In: the text, the mode ("reject" | "strip"; null =
        /// the default "reject") and the categories (null = ["secret", "pii"]). Out: the result. Why: SCREEN-01..14.
        /// 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing.
        /// </summary>
        public ScreenResult ScreenText(string text, string mode = "reject", IList<string> categories = null)
        {
            if (text == null || !WellFormed(text)) return ScreenResult.Fail(400, "invalid_text");
            mode ??= "reject";
            if (mode != "reject" && mode != "strip") return ScreenResult.Fail(400, "invalid_mode");
            categories ??= new[] { "secret", "pii" };
            if (categories.Count == 0 || categories.Any(c => c != "secret" && c != "pii")) return ScreenResult.Fail(400, "invalid_categories");
            if (Encoding.UTF8.GetByteCount(text) > _maxBytes) return ScreenResult.Fail(413, "text_too_large");
            try
            {
                var cats = new HashSet<string>(categories, StringComparer.Ordinal);
                var f = ScanCandidates(text, cats);
                var findings = ToFindings(text, f);
                if (mode == "reject" && findings.Count > 0)
                    return new ScreenResult { Ok = false, Status = 422, Error = "secrets_or_pii_detected", Findings = findings };
                var output = f.Count == 0 ? text : Redact(text, f);
                if (mode == "strip" && f.Count > 0)
                {
                    var again = ToFindings(output, ScanCandidates(output, cats));
                    if (again.Count > 0)
                        return new ScreenResult { Ok = false, Status = 422, Error = "secrets_or_pii_detected", Findings = findings.Concat(again.Select(x => x.Hidden(false))).ToList() };
                }
                if (output.IndexOf('\\') >= 0)
                {
                    var resolved = ResolveEscapes(output);
                    var hidden = new List<Finding>();
                    if (resolved.Text != output) hidden.AddRange(ToFindings(resolved.Text, ScanCandidates(resolved.Text, cats)).Select(x => x.Hidden(true)));
                    if (resolved.Unresolved)
                        hidden.Add(new Finding { Category = "secret", Label = "unresolved_escape", Start = -1, End = -1, Preview = "***", ValueHash = null, Encoded = true });
                    if (hidden.Count > 0)
                        return new ScreenResult { Ok = false, Status = 422, Error = "secrets_or_pii_detected", Findings = findings.Concat(hidden).ToList() };
                }
                return new ScreenResult { Ok = true, Status = 200, Text = output, Findings = findings };
            }
            catch (Exception)
            {
                return ScreenResult.Fail(500, "screening_failed");
            }
        }

        /// <summary>
        /// scan_text: the findings of the detectors whose category is asked for, combined (earliest start, then the longest
        /// span, then the lower detector number; no character in two findings), ordered by start, in code points. In: the
        /// text and the categories (null = both). Why: SCREEN-02..08, 11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Pure.
        /// </summary>
        public List<Finding> ScanText(string text, IList<string> categories = null)
        {
            var cats = new HashSet<string>(categories ?? new[] { "secret", "pii" }, StringComparer.Ordinal);
            return ToFindings(text, ScanCandidates(text, cats));
        }

        /// <summary>
        /// redact_text: each finding's span (code points) replaced by "[REDACTED:" + label + "]", in ONE left-to-right pass;
        /// findings with start -1 are skipped. In: the text and its findings. Out: the redacted text. Why: SCREEN-10. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static string RedactText(string text, IEnumerable<Finding> findings)
        {
            var units = CodePointToUnit(text);
            var spans = findings.Where(x => x.Start >= 0).OrderBy(x => x.Start)
                .Select(x => (Start: units[(int)x.Start], End: units[(int)x.End], x.Label)).ToList();
            var sb = new StringBuilder(text.Length);
            var at = 0;
            foreach (var (s, e, label) in spans)
            {
                sb.Append(text, at, s - at).Append("[REDACTED:").Append(label).Append(']');
                at = e;
            }
            return sb.Append(text, at, text.Length - at).ToString();
        }

        /// <summary>mask: n code points; n &lt; 16 gives n "*"; otherwise the first 2, n - 4 "*", the last 2. Why: SCREEN-12. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        public static string Mask(string value)
        {
            var runes = value.EnumerateRunes().Select(r => r.ToString()).ToList();
            var n = runes.Count;
            if (n < 16) return new string('*', n);
            return runes[0] + runes[1] + new string('*', n - 4) + runes[n - 2] + runes[n - 1];
        }

        /// <summary>
        /// resolve_escapes: repeats one left-to-right pass (\uXXXX, a surrogate pair of escapes, a lone surrogate to
        /// U+FFFD, \" \\ \/ \b \f \n \r \t) while the text holds an ESCAPE, at most 8 times. Out: the text and whether an
        /// ESCAPE is left. Why: SCREEN-13. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        public static EscapeResolution ResolveEscapes(string text)
        {
            var passes = 0;
            while (passes < 8 && HoldsEscape(text))
            {
                text = EscapePass(text);
                passes++;
            }
            return new EscapeResolution { Text = text, Unresolved = HoldsEscape(text) };
        }

        // ------------------------------------------------------------------ scanning

        /// <summary>Every enabled detector's candidates, combined. Out: the kept candidates (UTF-16 units), by start. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static List<Candidate> ScanCandidates(string text, HashSet<string> cats)
        {
            var all = new List<Candidate>();
            if (cats.Contains("secret"))
            {
                FindAll(all, text, PemFull, 1, null);
                PemCut(all, text);
                FindAll(all, text, OpenAi, 3, (m, b, a) => !IsW(b) && m.Value.Any(IsDigit));
                FindAll(all, text, StripeKey, 4, (m, b, a) => !IsW(b) && !IsW(a));
                FindAll(all, text, Aws, 5, (m, b, a) => !IsW(b) && !IsW(a));
                FindAll(all, text, GitHub, 6, (m, b, a) => !IsW(b) && !IsW(a));
                FindAll(all, text, Slack, 7, (m, b, a) => !IsW(b) && !IsW(a));
                FindAll(all, text, Google, 8, (m, b, a) => !IsW(b) && !IsW(a) && a != '-');
                FindAll(all, text, Whsec, 9, (m, b, a) => !IsW(b));
                Jwt(all, text);
                FindAll(all, text, Bearer, 11, (m, b, a) => !IsW(b) && (m.Groups[1].Value.Any(IsDigit) || LowerUpperPlaces(m.Groups[1].Value) >= 2), group: 1);
                FindAll(all, text, UrlCred, 12, (m, b, a) =>
                {
                    var v = m.Groups[1].Value;
                    return !v.StartsWith("[REDACTED:", StringComparison.Ordinal) && !Placeholders.Contains(AsciiLower(v));
                }, group: 1);
                KeyValueAssignments(all, text);
            }
            if (cats.Contains("pii"))
            {
                FindAll(all, text, Email, 14, (m, b, a) => !IsW(b) && !IsW(a) && !InUrlUserPart(text, m.Index));
                FindAll(all, text, Phone, 15, (m, b, a) => !IsDigit(b) && !IsDigit(a));
                Cards(all, text);
                FindAll(all, text, Ssn, 17, (m, b, a) => !IsW(b) && b != '-' && !IsW(a) && a != '-' && SsnOk(m.Value));
                FindAll(all, text, Ipv4, 18, (m, b, a) =>
                {
                    var e = m.Index + m.Length;
                    var dotDigit = a == '.' && e + 1 < text.Length && IsDigit(text[e + 1]);
                    return !IsW(b) && b != '.' && !IsW(a) && !dotDigit && Ipv4Ok(m.Value);
                });
                FindAll(all, text, Ipv6, 19, (m, b, a) => (b == null || (!IsW(b) && b != ':' && b != '.')) && (a == null || (!IsW(a) && a != ':')) && Ipv6Ok(m.Value));
            }
            var sorted = all.OrderBy(c => c.Start).ThenByDescending(c => c.End - c.Start).ThenBy(c => c.Detector).ToList();
            var kept = new List<Candidate>();
            var lastEnd = 0;
            foreach (var c in sorted)
                if (c.Start >= lastEnd) { kept.Add(c); lastEnd = c.End; }
            return kept;
        }

        /// <summary>
        /// find_all: repeatedly the leftmost match at or after pos; accepted (guard and check) -> a candidate (the match
        /// or group 1) and pos = the end of the match; otherwise pos = its start + 1. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static void FindAll(List<Candidate> output, string text, Regex re, int detector, Func<Match, char?, char?, bool> accept, int group = 0)
        {
            var pos = 0;
            while (pos <= text.Length)
            {
                var m = re.Match(text, pos);
                if (!m.Success) break;
                var end = m.Index + m.Length;
                char? before = m.Index > 0 ? text[m.Index - 1] : (char?)null;
                char? after = end < text.Length ? text[end] : (char?)null;
                if (accept == null || accept(m, before, after))
                {
                    var g = m.Groups[group];
                    output.Add(new Candidate(g.Index, g.Index + g.Length, detector));
                    pos = end > m.Index ? end : m.Index + 1;
                }
                else pos = m.Index + 1;
            }
        }

        /// <summary>Detector 2: a private key block cut off before its END line, found by hand (60 key characters). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static void PemCut(List<Candidate> output, string t)
        {
            var pos = 0;
            while (pos <= t.Length)
            {
                var h = PemHeader.Match(t, pos);
                if (!h.Success) break;
                int p = h.Index + h.Length, count = 0, end = -1;
                while (true)
                {
                    var q = p;
                    while (q < t.Length)
                    {
                        var c = t[q];
                        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '>' || c == '-') q++;
                        else if (c == '\\' && q + 3 < t.Length && t[q + 1] == 'r' && t[q + 2] == '\\' && t[q + 3] == 'n') q += 4;
                        else if (c == '\\' && q + 1 < t.Length && t[q + 1] == 'n') q += 2;
                        else break;
                    }
                    var r = q;
                    while (r < t.Length && IsB64(t[r])) r++;
                    if (r - q < 16) break;
                    count += r - q;
                    end = r;
                    p = r;
                }
                if (count >= 60) { output.Add(new Candidate(h.Index, end, 2)); pos = end; }
                else pos = h.Index + 1;
            }
        }

        /// <summary>Detector 10: a JWT, found by hand (linear): eyJ + 5 more S, ".", 5+ S, ".", 5+ S. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static void Jwt(List<Candidate> output, string t)
        {
            var pos = 0;
            while (pos < t.Length)
            {
                var i = t.IndexOf("eyJ", pos, StringComparison.Ordinal);
                if (i < 0) break;
                if (i > 0 && IsW(t[i - 1])) { pos = i + 1; continue; }
                var j = RunEnd(t, i, IsJwtChar);
                pos = j;
                if (j - i < 8 || j >= t.Length || t[j] != '.') continue;
                var k = RunEnd(t, j + 1, IsJwtChar);
                if (k - (j + 1) < 5 || k >= t.Length || t[k] != '.') continue;
                var e = RunEnd(t, k + 1, IsJwtChar);
                if (e - (k + 1) < 5) continue;
                output.Add(new Candidate(i, e, 10));
                pos = e;
            }
        }

        /// <summary>
        /// Detector 13: key = value matched on the ASCII lower case of the text; the value is read from the original text;
        /// "[REDACTED:" is tested before the value is measured; 8+ code points; then V (without a sentence's end) is not a
        /// placeholder, not a REFERENCE, and looks like a secret. Pure.
        /// Changed 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (spec fed6e7b, SCREEN-14 "token=$" * 28571): followed
        /// literally this is quadratic (every match re-read the same long value). Where each value ends, where its
        /// sentence-end run starts, the code-point counts and the next "(" or "[" are now lookup tables computed once,
        /// the instant refusals (REDACTED, length, a REFERENCE's first character, placeholder length) run first, and the
        /// remaining checks stop at their first decisive character. The answers are unchanged; only the time is.
        /// </summary>
        private static void KeyValueAssignments(List<Candidate> output, string t)
        {
            var lower = AsciiLower(t);
            var n = t.Length;
            // valueEnd[i]: where a value that starts at i ends (the stop rule of the spec), right to left
            var valueEnd = new int[n + 1];
            valueEnd[n] = n;
            for (var i = n - 1; i >= 0; i--)
            {
                var c = t[i];
                var stop = IsValueStop(c) || (c == '\\' && i + 1 < n && IsValueStop(t[i + 1]) && t[i + 1] != ';');
                valueEnd[i] = stop ? i : valueEnd[i + 1];
            }
            // trimStart[e]: the start of the run of . , ; : ! ? that ends at e
            var trimStart = new int[n + 1];
            for (var e = 0; e <= n; e++)
                trimStart[e] = e > 0 && ".,;:!?".IndexOf(t[e - 1]) >= 0 ? trimStart[e - 1] : e;
            // nextBracket[i]: the first "(" or "[" at or after i (n when none)
            var nextBracket = new int[n + 1];
            nextBracket[n] = n;
            for (var i = n - 1; i >= 0; i--) nextBracket[i] = t[i] == '(' || t[i] == '[' ? i : nextBracket[i + 1];
            var cp = UnitToCodePoint(t);

            var pos = 0;
            while (pos <= n)
            {
                var m = KeyValue.Match(lower, pos);
                if (!m.Success) break;
                var runStart = m.Index;
                while (runStart > 0 && m.Index - runStart <= 40 && IsKeyRunChar(lower[runStart - 1])) runStart--;
                if (m.Index - runStart > 40) { pos = m.Index + 1; continue; }
                var vs = m.Index + m.Length;
                if (t.AsSpan(vs).StartsWith("[REDACTED:", StringComparison.Ordinal)) { pos = m.Index + 1; continue; }
                var ve = valueEnd[vs];
                if (cp[ve] - cp[vs] >= 8 && ValueAccepted(t, vs, Math.Max(vs, trimStart[ve]), nextBracket))
                {
                    output.Add(new Candidate(vs, ve, 13));
                    pos = ve > m.Index ? ve : m.Index + 1;
                }
                else pos = m.Index + 1;
            }
        }

        /// <summary>
        /// The checks on V = t[vs..ve) in the spec's meaning (not a placeholder, not a REFERENCE, looks like a secret),
        /// ordered so the instant refusals come first and every scan stops at its first decisive character. In: the
        /// text, V's bounds and the next-bracket table. Out: whether V is a secret. Pure. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (spec fed6e7b).
        /// </summary>
        private static bool ValueAccepted(string t, int vs, int ve, int[] nextBracket)
        {
            if (ve > vs && "$<{%*".IndexOf(t[vs]) >= 0) return false; // REFERENCE: a variable, template or mask
            if (ve - vs <= 16 && Placeholders.Contains(AsciiLower(t.Substring(vs, ve - vs)))) return false;
            var b = nextBracket[vs];
            if (b < ve && NamesOnly(t, vs, b).Ok) return false; // REFERENCE: a call or an index
            var names = NamesOnly(t, vs, ve);
            if (names.Ok && names.HasDot && !names.HasDigit) return false; // REFERENCE: a dotted name
            for (var i = vs; i < ve; i++)
            {
                var c = t[i];
                if (IsDigit(c) || (c < '\u0080' && !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))) return true;
            }
            var places = 0;
            for (var i = vs; i + 1 < ve; i++) if (t[i] >= 'a' && t[i] <= 'z' && t[i + 1] >= 'A' && t[i + 1] <= 'Z') places++;
            return places >= 2;
        }

        /// <summary>
        /// Whether t[s..e) split at "." is NAMEs only (each a letter or "_" then letters, digits and "_"), stopping at the
        /// first character that breaks it; also whether it held a "." and a digit 0-9. Pure. Added 2026-11-10,
        /// session_012zDydZCZ4AChqhEZ4oVtaP (spec fed6e7b).
        /// </summary>
        private static (bool Ok, bool HasDot, bool HasDigit) NamesOnly(string t, int s, int e)
        {
            bool hasDot = false, hasDigit = false, partStart = true;
            if (e <= s) return (false, false, false);
            for (var i = s; i < e; i++)
            {
                var c = t[i];
                if (c == '.')
                {
                    if (partStart) return (false, true, hasDigit);
                    hasDot = true;
                    partStart = true;
                    continue;
                }
                var letter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
                if (partStart ? !letter : !(letter || IsDigit(c))) return (false, hasDot, hasDigit);
                if (IsDigit(c)) hasDigit = true;
                partStart = false;
            }
            return (!partStart, hasDot, hasDigit);
        }

        /// <summary>
        /// Detector 16: a card number: the LONGEST prefix of the match with 13-19 digits, ending at the match's end (after
        /// not W) or before a space or "-" inside it, grouped like a card, with a card network prefix and a valid Luhn. Pure.
        /// Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        /// </summary>
        private static void Cards(List<Candidate> output, string t)
        {
            var pos = 0;
            while (pos <= t.Length)
            {
                var m = Card.Match(t, pos);
                if (!m.Success) break;
                var s = m.Index;
                var e = s + m.Length;
                var found = -1;
                if (!(s > 0 && IsW(t[s - 1])))
                {
                    var allDigits = new string(m.Value.Where(IsDigit).ToArray());
                    if (CardPrefix.IsMatch(allDigits))
                    {
                        for (var end = e; end > s && found < 0; end--)
                        {
                            var atEnd = end == e && !(e < t.Length && IsW(t[e]));
                            var inside = end < e && (t[end] == ' ' || t[end] == '-');
                            if (!atEnd && !inside) continue;
                            var prefix = t.Substring(s, end - s);
                            var digits = new string(prefix.Where(IsDigit).ToArray());
                            if (digits.Length < 13 || digits.Length > 19) continue;
                            var groups = prefix.Split(' ', '-');
                            if (groups.Take(groups.Length - 1).Any(g => g.Length < 4)) continue;
                            if (Luhn(digits)) found = end;
                        }
                    }
                }
                if (found >= 0) { output.Add(new Candidate(s, found, 16)); pos = found; }
                else pos = s + 1;
            }
        }

        // ------------------------------------------------------------------ checks (pure)

        /// <summary>A digit 0-9 (ASCII only). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsDigit(char c) => c >= '0' && c <= '9';
        /// <summary>A digit 0-9; none is not. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsDigit(char? c) => c.HasValue && IsDigit(c.Value);
        /// <summary>W = [A-Za-z0-9_]. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsW(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || IsDigit(c) || c == '_';
        /// <summary>In W; none is not. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsW(char? c) => c.HasValue && IsW(c.Value);
        /// <summary>A key character of detector 2: [A-Za-z0-9+/=]. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsB64(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || IsDigit(c) || c == '+' || c == '/' || c == '=';
        /// <summary>S of detector 10: [A-Za-z0-9_-]. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsJwtChar(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || IsDigit(c) || c == '_' || c == '-';
        /// <summary>The run before detector 13: [a-z0-9_.-] in LOWER. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsKeyRunChar(char c) => (c >= 'a' && c <= 'z') || IsDigit(c) || c == '_' || c == '.' || c == '-';
        /// <summary>Where detector 13's value ends: space, tab, LF, CR, FF, VT, ' " ;. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsValueStop(char c) => c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' || c == '\'' || c == '"' || c == ';';

        /// <summary>The end of the run of characters accepted by <paramref name="ok"/> that starts at i. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static int RunEnd(string t, int i, Func<char, bool> ok)
        {
            while (i < t.Length && ok(t[i])) i++;
            return i;
        }

        /// <summary>Places where a letter a-z is directly followed by a letter A-Z. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static int LowerUpperPlaces(string v)
        {
            var n = 0;
            for (var i = 0; i + 1 < v.Length; i++) if (v[i] >= 'a' && v[i] <= 'z' && v[i + 1] >= 'A' && v[i + 1] <= 'Z') n++;
            return n;
        }

        /// <summary>The email guard: false when the nearest "/", "@", space, tab, CR or LF before the match ends "://". Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool InUrlUserPart(string t, int start)
        {
            for (var k = start - 1; k >= 0; k--)
            {
                var c = t[k];
                if (c == '/' || c == '@' || c == ' ' || c == '\t' || c == '\r' || c == '\n')
                    return k >= 2 && t[k - 2] == ':' && t[k - 1] == '/' && c == '/';
            }
            return false;
        }

        /// <summary>The SSN check: area not 000, 666 or 9xx; group not 00; serial not 0000. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool SsnOk(string v) =>
            v.Substring(0, 3) != "000" && v.Substring(0, 3) != "666" && v[0] != '9' && v.Substring(4, 2) != "00" && v.Substring(7, 4) != "0000";

        /// <summary>The IPv4 check: numbers 0-255 without leading zeros, a public address, last number not 0. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool Ipv4Ok(string v)
        {
            var parts = v.Split('.');
            var n = new int[4];
            for (var i = 0; i < 4; i++)
            {
                if (parts[i].Length > 1 && parts[i][0] == '0') return false;
                n[i] = int.Parse(parts[i]);
                if (n[i] > 255) return false;
            }
            if (n[0] == 0 || n[0] == 10 || n[0] == 127 || n[0] >= 224) return false;
            if (n[0] == 169 && n[1] == 254) return false;
            if (n[0] == 172 && n[1] >= 16 && n[1] <= 31) return false;
            if (n[0] == 192 && n[1] == 168) return false;
            return n[3] != 0;
        }

        /// <summary>The IPv6 check: "::" at most once and never ":::", 8 groups (or at most 7 around "::"), 1-4 hex each, the first group in 0x2000-0x3fff. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool Ipv6Ok(string v)
        {
            if (v.Contains(":::")) return false;
            var dc = v.IndexOf("::", StringComparison.Ordinal);
            List<string> groups;
            string first;
            if (dc >= 0)
            {
                if (v.IndexOf("::", dc + 1, StringComparison.Ordinal) >= 0) return false;
                var left = v.Substring(0, dc);
                var right = v.Substring(dc + 2);
                var lg = left.Length == 0 ? new List<string>() : left.Split(':').ToList();
                var rg = right.Length == 0 ? new List<string>() : right.Split(':').ToList();
                if (lg.Count + rg.Count > 7) return false;
                groups = lg.Concat(rg).ToList();
                first = lg.Count == 0 ? "0" : lg[0];
            }
            else
            {
                groups = v.Split(':').ToList();
                if (groups.Count != 8) return false;
                first = groups[0];
            }
            if (groups.Any(g => g.Length < 1 || g.Length > 4)) return false;
            var f = Convert.ToInt32(first, 16);
            return f >= 0x2000 && f <= 0x3fff;
        }

        /// <summary>The Luhn check on a digit string. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool Luhn(string digits)
        {
            var sum = 0;
            for (var i = 0; i < digits.Length; i++)
            {
                var d = digits[digits.Length - 1 - i] - '0';
                if (i % 2 == 1) { d *= 2; if (d > 9) d -= 9; }
                sum += d;
            }
            return sum % 10 == 0;
        }

        // ------------------------------------------------------------------ findings, redaction, escapes (pure)

        /// <summary>The kept candidates as findings in code points, with preview and value_hash. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private List<Finding> ToFindings(string text, List<Candidate> kept)
        {
            if (kept.Count == 0) return new List<Finding>();
            var cp = UnitToCodePoint(text);
            return kept.Select(c =>
            {
                var value = text.Substring(c.Start, c.End - c.Start);
                return new Finding
                {
                    Category = c.Detector <= 13 ? "secret" : "pii", Label = Labels[c.Detector], Start = cp[c.Start], End = cp[c.End],
                    Preview = Mask(value),
                    ValueHash = _hashKey == null ? null : Convert.ToHexString(HMACSHA256.HashData(_hashKey, Encoding.UTF8.GetBytes(value))).ToLowerInvariant(),
                    Encoded = false,
                };
            }).ToList();
        }

        /// <summary>Replaces each kept candidate (UTF-16 units) with its marker, in one left-to-right pass. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string Redact(string text, List<Candidate> kept)
        {
            var sb = new StringBuilder(text.Length);
            var at = 0;
            foreach (var c in kept)
            {
                sb.Append(text, at, c.Start - at).Append("[REDACTED:").Append(Labels[c.Detector]).Append(']');
                at = c.End;
            }
            return sb.Append(text, at, text.Length - at).ToString();
        }

        /// <summary>cp[i] = the code points before UTF-16 index i (length n + 1). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static int[] UnitToCodePoint(string t)
        {
            var cp = new int[t.Length + 1];
            for (var i = 0; i < t.Length; i++) cp[i + 1] = cp[i] + (char.IsLowSurrogate(t[i]) ? 0 : 1);
            return cp;
        }

        /// <summary>units[k] = the UTF-16 index of code point k (length = code points + 1). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static int[] CodePointToUnit(string t)
        {
            var units = new List<int>();
            for (var i = 0; i < t.Length; i++) if (!char.IsLowSurrogate(t[i])) units.Add(i);
            units.Add(t.Length);
            return units.ToArray();
        }

        /// <summary>Well-formed UTF-16: every surrogate is part of a pair. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool WellFormed(string t)
        {
            for (var i = 0; i < t.Length; i++)
            {
                if (char.IsHighSurrogate(t[i]))
                {
                    if (i + 1 >= t.Length || !char.IsLowSurrogate(t[i + 1])) return false;
                    i++;
                }
                else if (char.IsLowSurrogate(t[i])) return false;
            }
            return true;
        }

        /// <summary>Maps A-Z to a-z and nothing else, so positions stay. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string AsciiLower(string s)
        {
            var a = s.ToCharArray();
            for (var i = 0; i < a.Length; i++) if (a[i] >= 'A' && a[i] <= 'Z') a[i] = (char)(a[i] + 32);
            return new string(a);
        }

        /// <summary>A hex digit, either case. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool IsHex(char c) => IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

        /// <summary>The value of a \uXXXX escape at i, or -1. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static int UEscape(string t, int i)
        {
            if (i < 0 || i + 5 >= t.Length) return -1;
            if (t[i] != '\\' || t[i + 1] != 'u' || !IsHex(t[i + 2]) || !IsHex(t[i + 3]) || !IsHex(t[i + 4]) || !IsHex(t[i + 5])) return -1;
            return Convert.ToInt32(t.Substring(i + 2, 4), 16);
        }

        /// <summary>True when the text holds an ESCAPE (\uXXXX, or \ followed by one of " \ / b f n r t). Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static bool HoldsEscape(string t)
        {
            for (var i = t.IndexOf('\\'); i >= 0 && i + 1 < t.Length; i = t.IndexOf('\\', i + 1))
            {
                if ("\"\\/bfnrt".IndexOf(t[i + 1]) >= 0 || UEscape(t, i) >= 0) return true;
            }
            return false;
        }

        /// <summary>One left-to-right pass replacing every ESCAPE. Pure. Phase D wave 1, 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.</summary>
        private static string EscapePass(string t)
        {
            var sb = new StringBuilder(t.Length);
            var i = 0;
            while (i < t.Length)
            {
                if (t[i] != '\\' || i + 1 >= t.Length) { sb.Append(t[i]); i++; continue; }
                var c = t[i + 1];
                switch (c)
                {
                    case '"': case '\\': case '/': sb.Append(c); i += 2; continue;
                    case 'b': sb.Append('\b'); i += 2; continue;
                    case 'f': sb.Append('\f'); i += 2; continue;
                    case 'n': sb.Append('\n'); i += 2; continue;
                    case 'r': sb.Append('\r'); i += 2; continue;
                    case 't': sb.Append('\t'); i += 2; continue;
                }
                var u = UEscape(t, i);
                if (u < 0) { sb.Append('\\'); i++; continue; }
                if (u >= 0xD800 && u <= 0xDBFF)
                {
                    var low = UEscape(t, i + 6);
                    if (low >= 0xDC00 && low <= 0xDFFF)
                    {
                        sb.Append((char)u).Append((char)low);
                        i += 12;
                        continue;
                    }
                    sb.Append('�');
                }
                else if (u >= 0xDC00 && u <= 0xDFFF) sb.Append('�');
                else sb.Append((char)u);
                i += 6;
            }
            return sb.ToString();
        }
    }
}
