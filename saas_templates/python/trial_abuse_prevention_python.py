# Repaired 2026-11-03: the device check counts OTHER accounts on the device (a device already tied to this account
#   no longer passes by itself); the ledger row records its user_id; timezone-aware UTC times.
# Why: the suite failed on CI (it was listed in ci/baseline.json). Fixed by a free model from a
# continuity handoff, then reviewed by Claude. 2026-11-03, session c6ee9a72.
# Touches: SQLite only.
import sqlite3
import datetime
import hashlib
import json
from typing import Dict, Any, Optional, Tuple

TRIAL_DAYS = 14
CHALLENGE_RETRY_AFTER = 86400  # 24 hours in seconds


class TrialAbusePrevention:
    def __init__(self, db_path: str = ":memory:"):
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
        now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(hours=24)
        count = self._fetchone(
            """
            SELECT COUNT(*) as cnt FROM signups
            WHERE ip = ?
              AND datetime(created_at) > ?
            """,
            (ip, cutoff.isoformat()),
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
    def check_device_fingerprint(self, user_id: int, device: Dict[str, str]) -> Dict[str, Any]:
        device_hash = self._hash_device(device)
        # Count distinct OTHER users with this device_hash
        count = self._fetchone(
            """
            SELECT COUNT(DISTINCT user_id) as cnt FROM device_fingerprints
            WHERE device_hash = ? AND user_id != ?
            """,
            (device_hash, user_id),
        )
        matching_users = count["cnt"] if count else 0

        if matching_users < 2:
            decision = "PASS"
        elif matching_users <= 5:
            decision = "CHALLENGE"
        else:
            decision = "FAIL"

        self.why_chain(
            user_id=user_id,
            gate_name="device_fingerprint",
            decision=decision,
            rule_inputs={"device_hash": device_hash, "matching_users": matching_users},
            rule_outputs={},
        )
        return {"decision": decision, "matching_users": matching_users}

    # Gate 5: TRIAL_PAYMENT_TIMING
    def check_trial_payment_timing(self, user_id: int) -> Dict[str, Any]:
        user = self._fetchone(
            """
            SELECT trial_started_at, payment_added_date FROM trial_abuse_ledger
            WHERE user_id = ?
            """,
            (user_id,),
        )
        if not user:
            return {"decision": "FAIL", "reason": "user_not_found"}

        trial_start = datetime.datetime.fromisoformat(user["trial_started_at"])
        now = datetime.datetime.now(datetime.timezone.utc)
        # Ensure trial_start is timezone-aware for subtraction
        if trial_start.tzinfo is None:
            trial_start = trial_start.replace(tzinfo=datetime.timezone.utc)
        days_elapsed = (now - trial_start).days

        payment_added = user["payment_added_date"]
        payment_added_date = (
            datetime.datetime.fromisoformat(payment_added) if payment_added else None
        )
        if payment_added_date and payment_added_date.tzinfo is None:
            payment_added_date = payment_added_date.replace(tzinfo=datetime.timezone.utc)

        if payment_added_date and payment_added_date > trial_start:
            if days_elapsed < TRIAL_DAYS + 5:
                decision = "PASS"
            elif days_elapsed > TRIAL_DAYS + 30 and payment_added_date > trial_start + datetime.timedelta(days=TRIAL_DAYS):
                decision = "CHALLENGE"
            else:
                decision = "PASS"
        else:
            # No payment added yet
            if days_elapsed > 90:
                decision = "FAIL"
            else:
                decision = "PASS"

        self.why_chain(
            user_id=user_id,
            gate_name="trial_payment_timing",
            decision=decision,
            rule_inputs={"trial_duration": days_elapsed, "payment_delay": payment_added_date.isoformat() if payment_added_date else None},
            rule_outputs={},
        )
        return {"decision": decision}

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
        email_gate = self.check_email_trial_history(email)
        ip_gate = self.check_ip_signup_rate_limit(ip)

        if email_gate["decision"] == "FAIL":
            return {"error": "email_has_trial_history", "code": 409}
        if ip_gate["decision"] == "FAIL":
            return {"error": "too_many_signups_from_ip", "code": 429, "retry_after": CHALLENGE_RETRY_AFTER}

        # Create user record
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cur = self._execute(
            """
            INSERT INTO trial_abuse_ledger
            (email, ip, signup_date, trial_started_at, subscription_status, gate_flags)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                ip,
                now,
                now,
                None,
                json.dumps({"email": email_gate["decision"], "ip": ip_gate["decision"]}),
            ),
        )
        user_id = cur.lastrowid
        # Set user_id column to match the primary key id
        self._execute(
            "UPDATE trial_abuse_ledger SET user_id = ? WHERE id = ?",
            (user_id, user_id),
        )

        # Record signup for IP rate limiting
        self._execute(
            """
            INSERT INTO signups (ip) VALUES (?)
            """,
            (ip,),
        )

        # Record device fingerprint
        device_hash = self._hash_device(device)
        self._execute(
            """
            INSERT INTO device_fingerprints
            (user_id, device_hash, user_agent, screen_resolution, timezone)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                user_id,
                device_hash,
                device.get("user_agent", ""),
                device.get("screen_resolution", ""),
                device.get("timezone", ""),
            ),
        )

        # Challenge handling
        response = {"success": True}
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
        payment_gate = self.check_payment_method_history(stripe_payment_method_id)
        timing_gate = self.check_trial_payment_timing(user_id)
        chargeback_gate = self.check_chargeback_history(user_id)

        if payment_gate["decision"] == "FAIL":
            return {"error": "payment_method_used_for_multiple_trials", "code": 403}
        if timing_gate["decision"] == "FAIL":
            return {"error": "trial_ended_no_payment_cannot_retry", "code": 403}
        if chargeback_gate["decision"] == "FAIL":
            return {"error": "chargeback_history_requires_prepayment", "code": 403}

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
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
