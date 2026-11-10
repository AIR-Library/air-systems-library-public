"""Tests for secret_pii_screening_python (docs/specs/secret_pii_screening.md), with the spec's fixed vectors.

Key-shaped values are built from two or more pieces at run time, as the spec writes them, so a repository secret
scanner never blocks a commit. Why: Phase D wave 1, owner request 2026-11-10. 2026-11-10,
session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing (no database, files, network or money).
"""
import json
import time

import pytest

from secret_pii_screening_python import (
    ScreeningConfigError,
    mask,
    new_screener,
    redact_text,
    resolve_escapes,
)

K1 = "sk-" + "abcdEFGH12345678ijklMNOP"
K2 = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
K3 = "pk_" + "test_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
K4 = "AKIA" + "IOSFODNN7EXAMPLE"
K5 = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"
K6 = "github_pat_" + "11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789"
K7 = "xoxb-" + "1234567890-abcdefghijklmnopqrstuvwx"
K8 = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
K9 = "whsec_" + "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
J = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" + "."
     + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
B = "-----BEGIN RSA " + "PRIVATE KEY-----"
E = "-----END RSA " + "PRIVATE KEY-----"
L1 = "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumga0R2LiajO16aI4Uxa2b9nb"
L2 = "AKELFOxNOFICTIONALKEYMATERIALFORTESTINGPURPOSESONLY1234567890AB"
P1 = B + "\n" + L1 + "\n" + L2 + "\n" + E
P2 = (B + "\n" + "Proc-Type: 4,ENCRYPTED\n" + "DEK-Info: AES-256-CBC,A1B2C3D4E5F60718293A4B5C6D7E8F90\n" + "\n" + L1
      + "\n" + E)
P3 = B + "\n" + "api_key=looksLikeASecretButItsJustPemBase64Content\n" + E
P4 = B + "\n" + L1 + "\n" + L2 + " (cut"
G = ("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----" + "\nVersion: GnuPG v2\n\n" + L1 + "\n" + L2 + "\n=AbCd\n"
     + "-----END PGP " + "PRIVATE KEY BLOCK-----")
HASH_KEY = bytes(range(32))
T = "Contact jane@example.com or call 555-123-4567 for help."

CLEAN = [
    "User: let's plan the export feature.\nAssistant: I built the CSV export button and will add a progress bar.\n",
    "def get_cache_key(user_id):\n    return f'user:{user_id}'\n\nclass TokenBucket:\n    def __init__(self, capacity):\n"
    "        self.capacity = capacity\n",
    "Please reset your password before the next login.",
    "version 1.2.3.4.5 released at 12:30:45 on 2026-11-10, build 20261110123045, order 1234567890",
]

V02 = [
    ("here is my key: " + K1, [("openai_style_api_key", 16, 43)]),
    ("STRIPE_KEY=" + K2, [("stripe_style_api_key", 11, 43)]),
    (K3 + " used in the demo", [("stripe_style_api_key", 0, 32)]),
    ("AWS_ACCESS_KEY_ID=" + K4, [("aws_access_key_id", 18, 38)]),
    ("token: " + K5, [("github_token", 7, 47)]),
    ("use " + K6 + " now", [("github_token", 4, 62)]),
    (K7, [("slack_token", 0, 40)]),
    ("key=" + K8 + "&x=1", [("google_api_key", 4, 43)]),
    ("secret " + K9 + ".", [("webhook_signing_secret", 7, 45)]),
    ("Authorization token captured: " + J, [("jwt", 30, 162)]),
    ("ASIA" + "IOSFODNN7EXAMPLE", [("aws_access_key_id", 0, 20)]),
    ("task-" + "abcdEFGH12345678ijklMNOP", []),
    ("X" + K4, []),
    (K2 + "_x", []),
    ("class sk-spinner-three-bounce is used", []),
]

V03 = [
    ("a " + P1 + " b", [("pem_private_key", 2, 192)]),
    (P2, [("pem_private_key", 0, 205)]),
    (P3, [("pem_private_key", 0, 112)]),
    ("api_key=looksLikeASecretButItsJustPemBase64Content", [("generic_key_value_assignment", 8, 50)]),
    ("x " + P4, [("pem_private_key", 2, 162)]),
    ("-" + B + "\n-" + L1 + "\n-" + L2 + "\n-" + E, [("pem_private_key", 1, 163)]),
    ("> " + B + "\n> " + L1 + "\n> " + L2 + "\n> " + E, [("pem_private_key", 2, 198)]),
    (G, [("pem_private_key", 0, 227)]),
    (B + "\n" + "A" * 30 + "\\n" + "A" * 30, [("pem_private_key", 0, 94)]),
    (B + "\n" + "A" * 29 + "\\n" + "A" * 30, []),
    (B + "\n" + "A" * 59, []),
    ("Look for the line " + B + " in the file.", []),
]

V04 = [
    ("curl -H 'Authorization: Bearer abc123DEF456ghi789JKL'", [("bearer_token", 31, 52)]),
    ("authorization: BEARER abc123DEF456ghi789JKL", [("bearer_token", 22, 43)]),
    ("Bearer authentication is required", []),
    ("Bearer " + J, [("jwt", 7, 139)]),
    ("postgres://app:S3cr3t-Pa55@db.internal:5432/app", [("url_credentials", 15, 26)]),
    ("ssh://git:hunter2secret@host/repo", [("url_credentials", 10, 23)]),
    ("https://user:password@example.com/", []),
    ("https://jane@example.com/x", []),
    ("redis://:Sup3rS3cretValue@cache.example.com:6379/0", [("url_credentials", 9, 25)]),
    ("http://localhost:8080/@foo and https://example.com/a:b@c", []),
    ("Our API uses Bearer authentication.", []),
    ("Send the header with bearer token-based auth", []),
]

GKV = "generic_key_value_assignment"
V05 = [
    ("DB_PASSWORD=Sup3rS3cretValue!\n", [(GKV, 12, 29)]),
    ("internal_api_key: \"zx91-nq7f-88ab-lorem\"", [(GKV, 19, 39)]),
    ("{\"password\": \"hunter2hunter2\"}", [(GKV, 14, 28)]),
    ("{\\\"password\\\":\\\"hunter2hunter2\\\"}", [(GKV, 16, 30)]),
    ("db_password: CorrectHorseBatteryStaple", [(GKV, 13, 38)]),
    ("the db_password: CorrectHorseBatteryStaple9 I mentioned", [(GKV, 17, 43)]),
    ("password: DOMAIN\\Administrator1", [(GKV, 10, 31)]),
    ("API_KEY = 'Zx91Nq7f88ab'", [(GKV, 11, 23)]),
    ("token=abc12345;next", [(GKV, 6, 14)]),
    ("password: p\u00e4ssw\u00f6rd123", [(GKV, 10, 21)]),
    ("a" * 40 + "token=abc12345def", [(GKV, 46, 57)]),
    ("a" * 41 + "token=abc12345def", []),
    ("API_KEY=your_key_here", []),
    ("password: changeme", []),
    ("pwd=abc123", []),
    ("Secret: whatever the team decides", []),
    ("password: WordPress", []),
    ("My favorite crypto token: Ethereum has been volatile", []),
    ("class TokenBucket:", []),
    ("Please reset your password before the next login.", []),
    ("secrets: abc12345def", []),
    ("password: gr\u00f6\u00dferes", []),
    ("password: [REDACTED:generic_key_value_assignment]", []),
    ("'password' => 'Sup3rS3cretValue!',", [(GKV, 15, 32)]),
    ("password := \"Sup3rS3cretValue!\"", [(GKV, 13, 30)]),
    ("password: hunter2!", [(GKV, 10, 18)]),
    ("password: P@ss(w0rd)1x", [(GKV, 10, 22)]),
    ("token: ab12.cd34.ef56gh78", [(GKV, 7, 25)]),
    ("\u0130 token=abc12345", [(GKV, 8, 16)]),
    ("The password: required.", []),
    ("token: optional,", []),
    ("password: changeme.", []),
    ("password: undefined,", []),
    ("password = os.getenv(\"DB_PASSWORD\")", []),
    ("api_key = os.environ[\"API_KEY\"]", []),
    ("secret_key = settings.SECRET_KEY", []),
    ("apiKey: process.env.STRIPE_KEY,", []),
    ("token = getAccessTokenSilently();", []),
    ("password: req.body.password,", []),
    ("API_KEY=$API_KEY", []),
    ("token=${TOKEN}", []),
    ("api_key: <YOUR_API_KEY>", []),
    ("Password: ********", []),
    ("token: Optional[str] = None", []),
    ("password = models.CharField(max_length=128)", []),
    ("to\u212aen=abc12345def", []),
    ("password: abcdefgh\u0663", []),
]

V06 = [
    ("Contact jane@example.com or call 555-123-4567 for help.", [("email_address", 8, 24), ("phone_number", 33, 45)]),
    ("<jane.doe+tag@mail.example.co.uk>", [("email_address", 1, 32)]),
    ("see https://example.com/contact?email=jane@example.com", [("email_address", 38, 54)]),
    ("call (555) 123-4567 now", [("phone_number", 5, 19)]),
    ("+1 555-123-4567", [("phone_number", 0, 15)]),
    ("reach me at +442071838750.", [("phone_number", 12, 25)]),
    ("SSN 123-45-6789", [("ssn", 4, 15)]),
    ("order 5551234567 shipped", []),
    ("jane@example.com_backup", []),
    ("user@localhost and a@b", []),
    ("SSN 000-12-3456, 666-12-3456, 900-12-3456, 123-00-4567, 123-45-0000", []),
]

CC = "credit_card_number"
V07 = [
    ("card 4242 4242 4242 4242 exp 12/27", [(CC, 5, 24)]),
    ("5555-5555-5555-4444", [(CC, 0, 19)]),
    ("378282246310005", [(CC, 0, 15)]),
    ("card 4242 4242 4242 4242 123", [(CC, 5, 24)]),
    ("4242 4242 4242 4242 1234 5678", [(CC, 0, 19)]),
    ("4242 4242 4242 4241", []),
    ("1234 5678 1234 5670", []),
    ("ts 1700000000000 ms", []),
    ("42424242424242424242424", []),
    ("x4242424242424242", []),
    ("4242424242424242x", []),
    ("3782 822463 10005", [(CC, 0, 17)]),
    ("card 4222 2222 2222 2 end", [(CC, 5, 21)]),
    ("2 2 6 14 8 15 20 6 13", []),
    ("4 8 15 16 23 42 4 8 15 16 23 42 108", []),
]

IP = "ip_address"
V08 = [
    ("client 203.0.113.7 connected", [(IP, 7, 18)]),
    ("from 198.51.100.24.", [(IP, 5, 18)]),
    ("addr 2001:db8::8a2e:370:7334 ok", [(IP, 5, 28)]),
    ("[2001:0db8:0000:0000:0000:ff00:0042:8329]", [(IP, 1, 40)]),
    ("8.8.8.8 and 172.32.0.1 and 2606:4700:4700::1111", [(IP, 0, 7), (IP, 12, 22), (IP, 27, 47)]),
    ("127.0.0.1 10.0.0.5 192.168.1.1 172.16.0.1 169.254.1.1 0.0.0.0 224.0.0.1 255.255.255.255", []),
    ("999.1.1.1 and 256.1.1.1 and 08.8.8.8", []),
    ("1.2.3.4.5 and v8.8.8.8", []),
    ("12:30:45 and aa:bb:cc:dd:ee:ff", []),
    ("::1 and fe80::1 and fc00::1", []),
    ("db::add(x) and dead::beef", []),
    ("Version=1.0.0.0, Culture=neutral", []),
]

V11 = [
    ("\u00e9\U0001F600 a@b.co", [("email_address", 3, 9)]),
    ("token=" + K1, [("openai_style_api_key", 6, 33)]),
    ("Bearer " + K1, [("openai_style_api_key", 7, 34)]),
]

ALL_VECTORS = V02 + V03 + V04 + V05 + V06 + V07 + V08 + V11


def spans(findings):
    """(label, start, end) of each finding, for exact comparison. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    return [(f["label"], f["start"], f["end"]) for f in findings]


def check_vectors(vectors):
    """Assert scan_text gives exactly each vector's findings, and that reject mode agrees (422 with the same
    findings, or ok with the text unchanged). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    s = new_screener()
    for text, want in vectors:
        assert spans(s.scan_text(text)) == want, text
        r = s.screen_text(text)
        if want:
            assert r["ok"] is False and r["status"] == 422 and r["error"] == "secrets_or_pii_detected", text
            assert spans(r["findings"]) == want, text
        else:
            assert r == {"ok": True, "status": 200, "text": text, "findings": []}, text


# SCREEN-01
def test_screen_01_clean_texts_pass_in_both_modes():
    """The four clean texts are ok, unchanged, with findings [] in reject and strip mode. SCREEN-01.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    s = new_screener()
    for text in CLEAN:
        for mode in ("reject", "strip"):
            assert s.screen_text(text, mode) == {"ok": True, "status": 200, "text": text, "findings": []}


# SCREEN-02
def test_screen_02_key_shapes_and_near_misses():
    """Every key shape with its label and exact span; the four near-misses are not found. SCREEN-02.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V02)


# SCREEN-03
def test_screen_03_private_key_blocks():
    """A block is one finding with its encrypted header; cut-off, quoted and diff blocks; 60-character rule.
    SCREEN-03. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V03)


# SCREEN-04
def test_screen_04_bearer_and_url_credentials():
    """Bearer tokens and URL passwords are found with only the token or password as the span. SCREEN-04.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V04)


# SCREEN-05
def test_screen_05_key_value_assignments():
    """key = value in every form; placeholders, short values, words, references and redactions are not.
    SCREEN-05. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V05)


# SCREEN-06
def test_screen_06_email_phone_ssn():
    """Email addresses, phone numbers and SSNs, with their near-misses. SCREEN-06.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V06)


# SCREEN-07
def test_screen_07_card_numbers():
    """Card numbers need a network prefix and Luhn; groupings and short trailing numbers. SCREEN-07.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V07)


# SCREEN-08
def test_screen_08_ip_addresses():
    """Public IPv4 and global IPv6 only; private, versions, clock times and MAC addresses are not. SCREEN-08.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V08)


# SCREEN-09
def test_screen_09_reject_mode_holds_no_value_and_categories_filter():
    """Reject: 422 with exactly the two findings and no text or matched value anywhere in the result; with
    categories ["secret"] the same text is ok. SCREEN-09. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    s = new_screener(HASH_KEY)
    r = s.screen_text(T)
    assert r == {"ok": False, "error": "secrets_or_pii_detected", "status": 422, "findings": [
        {"category": "pii", "label": "email_address", "start": 8, "end": 24, "preview": "ja************om",
         "value_hash": "9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10", "encoded": False},
        {"category": "pii", "label": "phone_number", "start": 33, "end": 45, "preview": "************",
         "value_hash": "ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3", "encoded": False},
    ]}
    blob = json.dumps(r)
    assert "text" not in r
    for secret_part in ("jane@example.com", "555-123-4567", "Contact"):
        assert secret_part not in blob
    assert s.screen_text(T, "reject", ["secret"]) == {"ok": True, "status": 200, "text": T, "findings": []}


# SCREEN-10
def test_screen_10_strip_mode_redacts_and_rescreens():
    """Strip: every finding becomes a [REDACTED:label] marker and nothing else changes; the output is clean in
    reject mode, for every vector with findings; a match that appears once its neighbour is gone is 422.
    SCREEN-10. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    s = new_screener(HASH_KEY)
    r = s.screen_text(T, "strip")
    assert r["ok"] is True and r["status"] == 200
    assert r["text"] == "Contact [REDACTED:email_address] or call [REDACTED:phone_number] for help."
    assert spans(r["findings"]) == [("email_address", 8, 24), ("phone_number", 33, 45)]
    assert s.screen_text(T, "strip", ["pii"]) == r
    for text, want in ALL_VECTORS:
        if not want:
            continue
        out = s.screen_text(text, "strip")
        assert out["ok"] is True and out["status"] == 200, text
        expected = text
        for label, start, end in reversed(want):
            expected = expected[:start] + "[REDACTED:" + label + "]" + expected[end:]
        assert out["text"] == expected, text
        again = s.screen_text(out["text"], "reject")
        assert again == {"ok": True, "status": 200, "text": out["text"], "findings": []}, text
    r = s.screen_text("jane@example.com555-123-4567", "strip")
    assert r["ok"] is False and r["status"] == 422 and r["error"] == "secrets_or_pii_detected"
    assert "text" not in r
    assert spans(r["findings"]) == [("phone_number", 16, 28), ("email_address", -1, -1)]


# SCREEN-11
def test_screen_11_overlaps_and_code_point_offsets():
    """Earliest start, then longest span, then earlier detector; offsets count code points (a 2-byte and a 4-byte
    character before the match). SCREEN-11. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    check_vectors(V11)
    s = new_screener()
    for text, _want in ALL_VECTORS:
        found = s.scan_text(text)
        for a, b in zip(found, found[1:]):
            assert a["end"] <= b["start"], text


# SCREEN-12
def test_screen_12_mask_value_hash_and_key_size():
    """mask rules, value_hash = HMAC-SHA256 under the configured key (the spec's values) and null without a key,
    a key under 32 bytes refused at construction. SCREEN-12. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
    assert mask("a" * 15) == "*" * 15
    assert mask("abcdefghijklmnop") == "ab************op"
    assert mask(K1) == "sk" + "*" * 23 + "OP"
    keyed = new_screener(HASH_KEY).scan_text(T)
    assert [f["value_hash"] for f in keyed] == [
        "9487588974759d303d5d44401791a603ad85fda9276d43f7436077d709d9da10",
        "ee171612a2f4984e73ec9377b4d10f2b76125f5adf8e4315f12e77ebb2cd41c3"]
    assert [f["preview"] for f in keyed] == ["ja************om", "************"]
    assert [f["value_hash"] for f in new_screener().scan_text(T)] == [None, None]
    with pytest.raises(ScreeningConfigError) as err:
        new_screener(bytes(range(31)))
    assert err.value.code == "invalid_hash_key"
    assert new_screener(bytes(range(32))) is not None


# SCREEN-13
def test_screen_13_hidden_escapes():
    """Secrets behind JSON escapes (E1-E8) are refused in both modes with encoded: true; mentions of escapes pass;
    strip succeeds when redaction already removed the secret; escapes left after 8 passes are refused.
    SCREEN-13. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    s = new_screener()
    bs = "\\"
    e1 = '{"note": "sk' + bs + 'u002dabcdEFGH12345678ijklMNOP"}'
    e2 = '{"outer": "{' + bs + '"k' + bs + '": ' + bs + '"sk' + bs + bs + 'u002dabcdEFGH12345678ijklMNOP' + bs + '"}"}'
    e3 = '{"msg": "the escape ' + bs + 'u00e9 prints an e-acute and ' + bs + 'n is a newline"}'
    e4 = '{"contact": "jane' + bs + 'u0040example.com"}'
    e5 = ('{"emoji": "' + bs + 'ud83d' + bs + 'ude00 ok", "path": "C:' + bs + bs + 'Users' + bs + bs + 'name' + bs + bs
          + 'notes.txt"}')
    e6 = '{"key": "' + P1.replace("\n", bs + "n") + '"}'
    e7 = '{"key": "' + P2.replace("\n", bs + "n") + '"}'
    e8 = bs * 600 + "n"

    def encoded(label):
        """The expected findings: one encoded finding with this label. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return [(label, -1, -1, True)]

    def shape(r):
        """(label, start, end, encoded) of each finding of a result. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP."""
        return [(f["label"], f["start"], f["end"], f["encoded"]) for f in r["findings"]]

    for text, label in ((e1, "openai_style_api_key"), (e2, "openai_style_api_key"), (e4, "email_address"),
                        (e7, "pem_private_key"), (e8, "unresolved_escape")):
        for mode in ("reject", "strip"):
            r = s.screen_text(text, mode)
            assert r["ok"] is False and r["status"] == 422 and r["error"] == "secrets_or_pii_detected", (text, mode)
            assert shape(r) == encoded(label), (text, mode)
            assert "text" not in r
    for text in (e3, e5):
        for mode in ("reject", "strip"):
            assert s.screen_text(text, mode) == {"ok": True, "status": 200, "text": text, "findings": []}
    r = s.screen_text(e6, "reject")
    assert r["status"] == 422 and shape(r) == [("pem_private_key", 9, 202, False)]
    r = s.screen_text(e6, "strip")
    assert r["ok"] is True and r["text"] == '{"key": "[REDACTED:pem_private_key]"}'
    assert resolve_escapes(e8)["unresolved"] is True
    assert resolve_escapes(bs + "u0041" + bs + "ud83d" + bs + "ude00" + bs + "ud800x") == {
        "text": "A\U0001F600\ufffdx", "unresolved": False}


# SCREEN-14
def test_screen_14_input_checks_and_hostile_inputs():
    """invalid_mode, invalid_categories and text_too_large come before any scan; each hostile 200,000-character
    input is screened in strip mode in under 2 seconds; an unpaired surrogate is 400 invalid_text (extra).
    SCREEN-14. 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    s = new_screener()
    assert s.screen_text("x", "mask") == {"ok": False, "error": "invalid_mode", "status": 400}
    assert s.screen_text("x", "reject", []) == {"ok": False, "error": "invalid_categories", "status": 400}
    assert s.screen_text("x", "reject", ["secret", "keys"]) == {
        "ok": False, "error": "invalid_categories", "status": 400}
    assert new_screener(max_bytes=9).screen_text("\u00e9" * 5) == {
        "ok": False, "error": "text_too_large", "status": 413}
    assert new_screener(max_bytes=10).screen_text("\u00e9" * 5)["ok"] is True
    # The checks come before any scan: a text with a secret still gets the input error.
    assert new_screener(max_bytes=9).screen_text(K1, "mask")["error"] == "invalid_mode"
    assert s.screen_text("\ud800", "reject") == {"ok": False, "error": "invalid_text", "status": 400}
    assert s.screen_text(None) == {"ok": False, "error": "invalid_text", "status": 400}
    hb = "-----BEGIN " + "PRIVATE KEY-----"
    hostile = ["a." * 100000, hb * 7400, "1234-" * 40000, "eyJ" * 66666, "xeyJ-" * 40000, "xsk-" * 50000,
               "password" + " " * 199990, "token=[REDACTED:" * 12500, "a://b:" * 33000, "ab:" * 66000,
               "1.1." * 50000, "\\n" * 100000, B + "\n" * 199969, B + ("\n" + "A" * 64) * 3000]
    for text in hostile:
        t0 = time.perf_counter()
        r = s.screen_text(text, "strip")
        took = time.perf_counter() - t0
        assert took < 2.0, (text[:20], took)
        assert r.get("error") in (None, "secrets_or_pii_detected"), (text[:20], r.get("error"))


# SCREEN-10
def test_redact_text_one_pass():
    """redact_text replaces each span in one left-to-right pass and keeps every other character (supports
    SCREEN-10). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    text = "a 12 b 34 c"
    fs = [{"label": "x", "start": 2, "end": 4}, {"label": "y", "start": 7, "end": 9}]
    assert redact_text(text, fs) == "a [REDACTED:x] b [REDACTED:y] c"
