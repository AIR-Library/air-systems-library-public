# Repaired 2026-11-03: the device check counts OTHER accounts on the device (a device already tied to this account
#   no longer passes by itself); the ledger row records its user_id; timezone-aware UTC times.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
# Amended 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-09/10/11/14/15, spec amended after review on PR 19):
#   the device gate counts OTHER users null-safely and decides FAIL >= 5, PASS < 2, PASS for a device the user
#   already has, else CHALLENGE; its row is written after the decision and only for PASS/CHALLENGE, and signup
#   runs it before recording anything. Payment timing is measured from the end of the trial (trial_days,
#   default 14) with floor division. All times come from an injectable clock.
import sqlite3
import datetime
import hashlib
import json
from typing import Dict, Any, Optional, Tuple

TRIAL_DAYS = 14
CHALLENGE_RETRY_AFTER = 86400  # 24 hours in seconds


def _iso(dt: datetime.datetime) -> str:
    """An aware datetime as UTC ISO-8601 with microseconds, so stored times compare correctly as text.
    2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (the signups table mixed SQLite's 'YYYY-MM-DD HH:MM:SS' with
    ISO 'T' strings, which compare wrongly). Touches nothing."""
    return dt.astimezone(datetime.timezone.utc).isoformat(timespec="microseconds")


def _parse(value: str) -> datetime.datetime:
    """A stored time as an aware UTC datetime (a naive value is taken as UTC). 2026-11-10,
    session_012zDydZCZ4AChqhEZ4oVtaP. Touches nothing."""
    dt = datetime.datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


class TrialAbusePrevention:
    def __init__(self, db_path: str = ":memory:", clock=None, trial_days: int = TRIAL_DAYS):
        """Open the gates' database.

        In: db_path; (added 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP) clock, a function returning an aware
        UTC datetime (default the wall clock), and trial_days (default 14; spec gate 5 "trial_days is
        configuration"). Why: deterministic tests (docs/specs/README.md) and TRIAL-10/11/15.
        Touches: SQLite (creates the tables)."""
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self.trial_days = trial_days
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        ddl = """
        CREATE TABLE IF NOT EXISTS trial_abuse_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            stripe_payment_method_id TEXT,
            ip TEXT,
            device_fingerprint TEXT,
            signup_date TEXT,
            trial_started_at TEXT,
            payment_added_date TEXT,
            subscription_status TEXT,
            chargeback_count INTEGER DEFAULT 0,
            refund_count INTEGER DEFAULT 0,
            gate_flags TEXT,
            alert_reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS device_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_hash TEXT,
            user_agent TEXT,
            screen_resolution TEXT,
            timezone TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS gate_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            gate_name TEXT,
            decision TEXT,
            rule_inputs TEXT,
            rule_outputs TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS signups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS stripe_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer TEXT,
            type TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS refunds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            status TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
        self.conn.executescript(ddl)
        self.conn.commit()

    def _execute(self, query: str, params: Tuple = ()):
        cur = self.conn.cursor()
        cur.execute(query, params)
        self.conn.commit()
        return cur

    def _fetchone(self, query: str, params: Tuple = ()) -> Optional[sqlite3.Row]:
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.fetchone()

    def _fetchall(self, query: str, params: Tuple = ()) -> list:
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()

    def _hash_device(self, device: Dict[str, str]) -> str:
        device_str = json.dumps(device, sort_keys=True)
        return hashlib.sha256(device_str.encode()).hexdigest()

    def why_chain(self, user_id: int, gate_name: str, decision: str,
                  rule_inputs: Dict[str, Any], rule_outputs: Dict[str, Any]):
        self._execute(
            """
            INSERT INTO gate_decisions
            (user_id, gate_name, decision, rule_inputs, rule_outputs)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                gate_name,
                decision,
                json.dumps(rule_inputs),
                json.dumps(rule_outputs),
            ),
        )

    # Gate 1: EMAIL_TRIAL_HISTORY
    def check_email_trial_history(self, email: str) -> Dict[str, Any]:
        prior = self._fetchone(
            """
            SELECT COUNT(*) as cnt FROM trial_abuse_ledger
            WHERE email = ?
              AND subscription_status IN ('completed', 'chargebacked')
            """,
            (email,),
        )
        prior_count = prior["cnt"] if prior else 0
        if prior_count == 0:
            decision = "PASS"
        elif prior_count == 1:
            decision = "CHALLENGE"
        else:
            decision = "FAIL"

        self.why_chain(
            user_id=0,
            gate_name="email_trial_history",
            decision=decision,
            rule_inputs={"email": email, "prior_count": prior_count},
            rule_outputs={},
        )
        return {"decision": decision, "prior_count": prior_count}

    # Gate 2: PAYMENT_METHOD_HISTORY
    def check_payment_method_history(self, payment_id: str) -> Dict[str, Any]:
        count = self._fetchone(
            """
            SELECT COUNT(*) as cnt FROM trial_abuse_ledger
            WHERE stripe_payment_method_id = ?
              AND subscription_status IN ('completed', 'chargebacked')
            """,
            (payment_id,),
        )
        prior_count = count["cnt"] if count else 0
        if prior_count < 2:
            decision = "PASS"
        elif prior_count == 2:
            decision = "CHALLENGE"
        else:
            decision = "FAIL"

        self.why_chain(
            user_id=0,
            gate_name="payment_method_history",
            decision=decision,
            rule_inputs={"payment_id": payment_id, "prior_count": prior_count},
            rule_outputs={},
        )
        return {"decision": decision, "prior_count": prior_count}

    # Gate 3: IP_SIGNUP_RATE_LIMIT
    def check_ip_signup_rate_limit(self, ip: str) -> Dict[str, Any]:
        """Gate 3: signups from this IP in the last 24 h: < 5 PASS, 5-9 CHALLENGE, >= 10 FAIL.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] Uses the injected clock and compares ISO strings written
        by _iso (it compared SQLite's datetime() text with an ISO 'T' string). Touches: SQLite."""
        now = self.clock()
        cutoff = now - datetime.timedelta(hours=24)
        count = self._fetchone(
            """
            SELECT COUNT(*) as cnt FROM signups
            WHERE ip = ?
              AND created_at > ?
            """,
            (ip, _iso(cutoff)),
        )
        signup_count = count["cnt"] if count else 0
        if signup_count < 5:
            decision = "PASS"
        elif 5 <= signup_count < 10:
            decision = "CHALLENGE"
        else:
            decision = "FAIL"

        self.why_chain(
            user_id=0,
            gate_name="ip_signup_rate_limit",
            decision=decision,
            rule_inputs={"ip": ip, "count": signup_count},
            rule_outputs={},
        )
        return {"decision": decision, "count": signup_count}

    # Gate 4: DEVICE_FINGERPRINT
    def _device_decision(self, user_id: Optional[int], device_hash: str) -> Tuple[str, int, bool]:
        """Decide gate 4 without writing anything. Out: (decision, other users on the device, user has it).

        Counts distinct OTHER users on the device, null-safe (a None user_id counts every user). Decision, in
        this order: FAIL if count >= 5; PASS if count < 2; PASS if this user already has a row for the device;
        CHALLENGE otherwise. Why: TRIAL-09/14 as amended 2026-11-10 (the old CHALLENGE range <= 5 overlapped
        FAIL at exactly 5). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (read)."""
        row = self._fetchone(
            """
            SELECT COUNT(DISTINCT user_id) as cnt FROM device_fingerprints
            WHERE device_hash = ? AND (? IS NULL OR user_id != ?)
            """,
            (device_hash, user_id, user_id),
        )
        others = row["cnt"] if row else 0
        known = False
        if user_id is not None:
            known = self._fetchone(
                "SELECT 1 FROM device_fingerprints WHERE device_hash = ? AND user_id = ? LIMIT 1",
                (device_hash, user_id),
            ) is not None
        if others >= 5:
            decision = "FAIL"
        elif others < 2 or known:
            decision = "PASS"
        else:
            decision = "CHALLENGE"
        return decision, others, known

    def _record_device(self, user_id: int, device: Dict[str, str], device_hash: str) -> None:
        """Write the user's device row unless it already exists. Called only after a PASS or CHALLENGE.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP (TRIAL-14). Touches: SQLite (device_fingerprints)."""
        if self._fetchone("SELECT 1 FROM device_fingerprints WHERE device_hash = ? AND user_id = ? LIMIT 1",
                          (device_hash, user_id)) is not None:
            return
        self._execute(
            """
            INSERT INTO device_fingerprints
            (user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, device_hash, device.get("user_agent", ""), device.get("screen_resolution", ""),
             device.get("timezone", ""), _iso(self.clock())),
        )

    def check_device_fingerprint(self, user_id: Optional[int], device: Dict[str, str]) -> Dict[str, Any]:
        """Gate 4 for a known (or, with None, a not yet created) user; records the device row after a PASS or
        CHALLENGE for a known user, never after a FAIL.

        In: user_id (or None), device {user_agent, screen_resolution, timezone, browser_language}.
        Out: {decision, matching_users}. Why: TRIAL-08/09/14 as amended 2026-11-10.
        2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP. Touches: SQLite (device_fingerprints, gate_decisions)."""
        device_hash = self._hash_device(device)
        decision, matching_users, known = self._device_decision(user_id, device_hash)
        self.why_chain(
            user_id=user_id if user_id is not None else 0,
            gate_name="device_fingerprint",
            decision=decision,
            rule_inputs={"device_hash": device_hash, "matching_users": matching_users, "known_device": known},
            rule_outputs={},
        )
        if decision != "FAIL" and user_id is not None:
            self._record_device(user_id, device, device_hash)
        return {"decision": decision, "matching_users": matching_users}

    # Gate 5: TRIAL_PAYMENT_TIMING
    def check_trial_payment_timing(self, user_id: int) -> Dict[str, Any]:
        """Gate 5, judged as a payment method is added (the payment date is now, from the clock).

        trial_end = the user's trial start + trial_days; days_after_trial = floor((now - trial_end) / 1 day),
        rounding toward negative infinity; earlier_payment = the ledger already has a payment_added_date for
        the user. PASS if days_after_trial < 5; FAIL if >= 90 and no earlier payment; CHALLENGE otherwise.
        A user with no ledger row is FAIL "user_not_found" (unchanged: fail closed).
        Out: {decision, days_after_trial, earlier_payment}. Why: TRIAL-10/11/15 as amended 2026-11-10 (it used
        days since the trial START with ad-hoc windows). 2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP.
        Touches: SQLite (read; gate_decisions)."""
        user = self._fetchone(
            """
            SELECT MIN(COALESCE(trial_started_at, signup_date)) AS started,
                   COUNT(payment_added_date) AS payments
            FROM trial_abuse_ledger WHERE user_id = ?
            """,
            (user_id,),
        )
        if not user or user["started"] is None:
            return {"decision": "FAIL", "reason": "user_not_found"}

        trial_end = _parse(user["started"]) + datetime.timedelta(days=self.trial_days)
        delta = self.clock() - trial_end
        days_after_trial = (delta.days * 86400 + delta.seconds) // 86400  # floor toward -infinity
        earlier_payment = user["payments"] > 0
        if days_after_trial < 5:
            decision = "PASS"
        elif days_after_trial >= 90 and not earlier_payment:
            decision = "FAIL"
        else:
            decision = "CHALLENGE"

        self.why_chain(
            user_id=user_id,
            gate_name="trial_payment_timing",
            decision=decision,
            rule_inputs={"trial_duration": self.trial_days, "payment_delay": days_after_trial,
                         "earlier_payment": earlier_payment},
            rule_outputs={},
        )
        return {"decision": decision, "days_after_trial": days_after_trial, "earlier_payment": earlier_payment}

    # Gate 6: CHARGEBACK_HISTORY
    def check_chargeback_history(self, user_id: int) -> Dict[str, Any]:
        # Count chargebacks from stripe_events
        stripe_cb = self._fetchone(
            """
            SELECT COUNT(*) as cnt FROM stripe_events
            WHERE customer = ?
              AND type LIKE '%chargeback%'
            """,
            (str(user_id),),
        )
        stripe_count = stripe_cb["cnt"] if stripe_cb else 0

        # Count refunds with status chargebacked
        refund_cb = self._fetchone(
            """
            SELECT COUNT(*) as cnt FROM refunds
            WHERE user_id = ?
              AND status = 'chargebacked'
            """,
            (user_id,),
        )
        refund_count = refund_cb["cnt"] if refund_cb else 0

        total = stripe_count + refund_count

        if total == 0:
            decision = "PASS"
        elif total == 1:
            decision = "CHALLENGE"
        else:
            decision = "FAIL"

        self.why_chain(
            user_id=user_id,
            gate_name="chargeback_history",
            decision=decision,
            rule_inputs={"stripe_count": stripe_count, "refund_count": refund_count},
            rule_outputs={},
        )
        return {"decision": decision, "total": total}

    # Signup flow
    def signup(self, email: str, password: str, ip: str, device: Dict[str, str]) -> Dict[str, Any]:
        """Run the signup gates, then record the user, the signup and the device.

        In: email, password (not stored here), the server-observed IP, the device. Out: {success: True,
        challenge?} or a FAIL body {error, code}: email 409, IP 429 (retry_after), device 403
        device_suspected_fraud. Every gate runs BEFORE anything is recorded, so a FAIL records no ledger,
        signup or device row. [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The device gate now runs here
        (TRIAL-09/14): signup used to record the device first, so a device farm never failed.
        Touches: SQLite (trial_abuse_ledger, signups, device_fingerprints, gate_decisions)."""
        email_gate = self.check_email_trial_history(email)
        ip_gate = self.check_ip_signup_rate_limit(ip)

        if email_gate["decision"] == "FAIL":
            return {"error": "email_has_trial_history", "code": 409}
        if ip_gate["decision"] == "FAIL":
            return {"error": "too_many_signups_from_ip", "code": 429, "retry_after": CHALLENGE_RETRY_AFTER}
        device_gate = self.check_device_fingerprint(None, device)
        if device_gate["decision"] == "FAIL":
            return {"error": "device_suspected_fraud", "code": 403}

        # Create user record
        now = _iso(self.clock())
        cur = self._execute(
            """
            INSERT INTO trial_abuse_ledger
            (email, ip, device_fingerprint, signup_date, trial_started_at, subscription_status, gate_flags, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                ip,
                self._hash_device(device),
                now,
                now,
                None,
                json.dumps({"email": email_gate["decision"], "ip": ip_gate["decision"],
                            "device": device_gate["decision"]}),
                now,
            ),
        )
        user_id = cur.lastrowid
        # Set user_id column to match the primary key id
        self._execute(
            "UPDATE trial_abuse_ledger SET user_id = ? WHERE id = ?",
            (user_id, user_id),
        )

        # Record signup for IP rate limiting
        self._execute("INSERT INTO signups (ip, created_at) VALUES (?, ?)", (ip, now))

        # Record the device AFTER its gate decided PASS or CHALLENGE
        self._record_device(user_id, device, self._hash_device(device))

        # Challenge handling
        response = {"success": True, "user_id": user_id}
        if device_gate["decision"] == "CHALLENGE":
            response["challenge"] = "email_confirm"  # spec: send "new device login detected"
        if email_gate["decision"] == "CHALLENGE":
            response["challenge"] = "email_confirm"
            # Flag user
            self._execute(
                """
                UPDATE trial_abuse_ledger
                SET gate_flags = json_set(gate_flags, '$.email', 'email_trial_attempt_2+')
                WHERE user_id = ?
                """,
                (user_id,),
            )
        if ip_gate["decision"] == "CHALLENGE":
            response["challenge"] = "captcha"

        return response

    # Payment flow
    def subscription_created(self, user_id: int, stripe_payment_method_id: str) -> Dict[str, Any]:
        """Payment flow: run gates 2, 5 and 6; on any FAIL return its 403 body, else record the payment.

        In: user_id, the payment method id. Out: {success: True} or {error, code: 403}.
        [2026-11-10, session_012zDydZCZ4AChqhEZ4oVtaP] The payment date comes from the injected clock.
        Touches: SQLite (trial_abuse_ledger, stripe_events, gate_decisions)."""
        payment_gate = self.check_payment_method_history(stripe_payment_method_id)
        timing_gate = self.check_trial_payment_timing(user_id)
        chargeback_gate = self.check_chargeback_history(user_id)

        if payment_gate["decision"] == "FAIL":
            return {"error": "payment_method_used_for_multiple_trials", "code": 403}
        if timing_gate["decision"] == "FAIL":
            return {"error": "trial_ended_no_payment_cannot_retry", "code": 403}
        if chargeback_gate["decision"] == "FAIL":
            return {"error": "chargeback_history_requires_prepayment", "code": 403}

        now = _iso(self.clock())
        # Update ledger
        self._execute(
            """
            UPDATE trial_abuse_ledger
            SET stripe_payment_method_id = ?, payment_added_date = ?, subscription_status = 'completed',
                gate_flags = json_set(gate_flags, '$.payment', ?)
            WHERE user_id = ?
            """,
            (
                stripe_payment_method_id,
                now,
                payment_gate["decision"],
                user_id,
            ),
        )

        # Record stripe event for payment
        self._execute(
            """
            INSERT INTO stripe_events (customer, type) VALUES (?, ?)
            """,
            (str(user_id), "payment_intent.succeeded"),
        )

        return {"success": True}

    # Utility methods for tests
    def add_refund(self, user_id: int, status: str):
        self._execute(
            """
            INSERT INTO refunds (user_id, status) VALUES (?, ?)
            """,
            (user_id, status),
        )

    def add_stripe_event(self, customer: str, event_type: str):
        self._execute(
            """
            INSERT INTO stripe_events (customer, type) VALUES (?, ?)
            """,
            (customer, event_type),
        )

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        row = self._fetchone(
            "SELECT * FROM trial_abuse_ledger WHERE user_id = ?", (user_id,)
        )
        return dict(row) if row else None

    def get_gate_decisions(self, user_id: int) -> list:
        rows = self._fetchall(
            "SELECT * FROM gate_decisions WHERE user_id = ?", (user_id,)
        )
        return [dict(r) for r in rows]
