# Trial Abuse Prevention

Reference contract for `saas_templates/<lang>/trial_abuse_prevention_<lang>.<ext>` in all eight languages. Every
language implements the same functions, error codes and return shapes, so the same input gives the
same answer everywhere. Common rules for every system are in [README.md](README.md).

## Required tests

Each language's tests file has at least one test for every id below, and names the id in the test's
name or in a comment on the line above it (for example `# TRIAL-01`), so a missing case is visible.

| id | what it proves |
|---|---|
| `TRIAL-01` | email_trial_history PASS → new email allowed |
| `TRIAL-02` | email_trial_history CHALLENGE → same email after 1 trial, flagged |
| `TRIAL-03` | email_trial_history FAIL → same email after 2 trials, rejected |
| `TRIAL-04` | payment_method_history PASS → new card allowed |
| `TRIAL-05` | payment_method_history FAIL → same card after 3 trials, rejected |
| `TRIAL-06` | ip_signup_rate_limit PASS → < 5 signups from IP, allowed |
| `TRIAL-07` | ip_signup_rate_limit FAIL → 10+ signups from IP, rejected 429 |
| `TRIAL-08` | device_fingerprint PASS → device < 2 users, allowed |
| `TRIAL-09` | device_fingerprint FAIL → device used by 5 or more other users, rejected |
| `TRIAL-10` | trial_payment_timing PASS → first payment 4 days after the trial ended (and one during the trial), allowed |
| `TRIAL-11` | trial_payment_timing FAIL → first payment 90 days after the trial ended, no earlier payment, rejected |
| `TRIAL-12` | chargeback_history PASS → no chargebacks, allowed |
| `TRIAL-13` | chargeback_history FAIL → 2+ chargebacks, requires prepayment |
| `TRIAL-14` | device_fingerprint boundaries → 4 other users CHALLENGE; exactly 5 FAIL, even when this user already has the device; a FAIL records no device row |
| `TRIAL-15` | trial_payment_timing boundaries → 5 and 89 days after the trial CHALLENGE; 90 days with an earlier payment CHALLENGE |

## Contract

```text
6 GATES (check in this order at signup + payment):

  1. EMAIL_TRIAL_HISTORY
     Query: SELECT * FROM trial_abuse_ledger WHERE email = ? AND subscription_status IN ('completed', 'chargebacked')
     Decision: PASS if no prior trials
              CHALLENGE if 1 prior trial (allow, but flag)
              FAIL if 2+ prior trials
     Log: why_chain(gate="email_trial_history", email, prior_count, decision)
     Action: if FAIL: return 409 {error: "email_has_trial_history"}
             if CHALLENGE: user.abuse_flags += "email_trial_attempt_2+"

  2. PAYMENT_METHOD_HISTORY
     Query: SELECT COUNT(*) FROM trial_abuse_ledger WHERE stripe_payment_method_id = ? AND subscription_status IN ('completed', 'chargebacked')
     Decision: PASS if count < 2
              CHALLENGE if count = 2
              FAIL if count >= 3
     Log: why_chain(gate="payment_method_history", payment_id, prior_count, decision)
     Action: if FAIL: return 403 {error: "payment_method_used_for_multiple_trials"}
             if CHALLENGE: user.abuse_flags += "payment_reuse_2x"

  3. IP_SIGNUP_RATE_LIMIT
     Query: SELECT COUNT(*) FROM signups WHERE ip = ? AND created_at > NOW() - INTERVAL 24 HOURS
     Decision: PASS if count < 5
              CHALLENGE if count >= 5 AND < 10
              FAIL if count >= 10
     Log: why_chain(gate="ip_signup_rate_limit", ip, count, limit)
     Action: if FAIL: return 429 {error: "too_many_signups_from_ip", retry_after: 86400}
             if CHALLENGE: require CAPTCHA or email confirmation

  4. DEVICE_FINGERPRINT
     device = {user_agent, screen_resolution, timezone, browser_language}
     device_hash = SHA256(device)
     Query: SELECT COUNT(DISTINCT user_id) FROM device_fingerprints
            WHERE device_hash = ? AND (? IS NULL OR user_id != ?)      -- count = OTHER users on this device
     Decision, in this order: FAIL if count >= 5
                              PASS if count < 2
                              PASS if this user already has a row for this device
                              CHALLENGE otherwise
     The device row is written AFTER the decision, and only for PASS or CHALLENGE. Signup runs this gate
     before it records the device (recording first made every later check pass, so a device farm never failed).
     Amended 2026-11-10 after review on PR 19. The old CHALLENGE range (<= 5) overlapped FAIL (>= 5) at exactly 5.
     Log: why_chain(gate="device_fingerprint", device_hash, matching_users, decision)
     Action: if FAIL: return 403 {error: "device_suspected_fraud"}
             if CHALLENGE: send email "new device login detected"

  5. TRIAL_PAYMENT_TIMING (judged when a payment method is being added, so the payment date is now)
     trial_end = user.created_at + trial_days (trial_days is configuration, default 14)
     days_after_trial = floor((now - trial_end) / 1 day)   -- negative while the trial is running; floor
                        rounds toward negative infinity (Math.floor, Math.floorDiv, div_euclid), not truncation
     earlier_payment = the ledger already has a payment_added_date for this user
     Decision: PASS if days_after_trial < 5
              FAIL if days_after_trial >= 90 AND NOT earlier_payment
              CHALLENGE otherwise (5 to 89 days after the trial, or 90+ days with an earlier payment)
     A first payment has no earlier date to compare: it is judged by the rule above with the payment date
     = now. Amended 2026-11-10 after review on PR 19.
     Log: why_chain(gate="trial_payment_timing", trial_duration, payment_delay, decision)
     Action: if FAIL: return 403 {error: "trial_ended_no_payment_cannot_retry"}
             if CHALLENGE: user.abuse_flags += "late_payment_entry"

  6. CHARGEBACK_HISTORY
     Query: SELECT COUNT(*) FROM stripe_events WHERE customer = stripe_customer_id AND type LIKE '%chargeback%'
     Also: SELECT COUNT(*) FROM refunds WHERE user_id = ? AND status = 'chargebacked'
     total_chargebacks = count from both queries
     Decision: PASS if count = 0
              CHALLENGE if count = 1
              FAIL if count >= 2
     Log: why_chain(gate="chargeback_history", chargebacks, decision)
     Action: if FAIL: return 403 {error: "chargeback_history_requires_prepayment"}
             if CHALLENGE: user.abuse_flags += "chargeback_1x"

INTEGRATION INTO AUTH FLOW:
  On signup(email, password):
    email_gate = check_email_trial_history(email)
    ip_gate = check_ip_signup_rate_limit(ip)

    if email_gate.decision == "FAIL": return 409
    if ip_gate.decision == "FAIL": return 429

    [create user]

    if email_gate.decision == "CHALLENGE": user.abuse_flags += "email_trial_attempt_2+"
    if ip_gate.decision == "CHALLENGE": [require CAPTCHA]

    [send verification email]

    # Log to abuse ledger
    abuse_entry = TrialAbuseLedger(
      user_id=user.id,
      email=email,
      ip=ip,
      signup_date=NOW(),
      trial_started_at=NOW(),
      gate_flags={email: email_gate.decision, ip: ip_gate.decision}
    )

INTEGRATION INTO PAYMENT FLOW:
  On subscription_created(user_id, stripe_payment_method_id):
    payment_gate = check_payment_method_history(stripe_payment_method_id)
    timing_gate = check_trial_payment_timing(user_id)
    chargeback_gate = check_chargeback_history(user_id)

    if any == "FAIL": return 403 with reason

    [create subscription]

    # Update abuse ledger
    abuse_entry.payment_added_date = NOW()
    abuse_entry.stripe_payment_method_id = stripe_payment_method_id
    abuse_entry.gate_flags.update({payment: payment_gate.decision, ...})

IMPLEMENTATION REQUIREMENTS:
  - trial_abuse_ledger table: (id, user_id, email, stripe_payment_method_id, ip, device_fingerprint, signup_date, trial_started_at, payment_added_date, subscription_status, chargeback_count, refund_count, gate_flags [JSON], alert_reason, created_at)
  - device_fingerprints table: (id, user_id, device_hash, user_agent, screen_resolution, timezone, created_at)
  - gate_decisions table: (id, user_id, gate_name, decision, rule_inputs [JSON], rule_outputs [JSON], created_at)
  - Response on FAIL: {error: "gate_name", message: "...", code: 409|403|429}
  - Response on CHALLENGE: {success: true, challenge: "captcha"|"email_confirm", ...}

TESTS REQUIRED:
  - **TRIAL-01** email_trial_history PASS → new email allowed
  - **TRIAL-02** email_trial_history CHALLENGE → same email after 1 trial, flagged
  - **TRIAL-03** email_trial_history FAIL → same email after 2 trials, rejected
  - **TRIAL-04** payment_method_history PASS → new card allowed
  - **TRIAL-05** payment_method_history FAIL → same card after 3 trials, rejected
  - **TRIAL-06** ip_signup_rate_limit PASS → < 5 signups from IP, allowed
  - **TRIAL-07** ip_signup_rate_limit FAIL → 10+ signups from IP, rejected 429
  - **TRIAL-08** device_fingerprint PASS → device < 2 users, allowed
  - **TRIAL-09** device_fingerprint FAIL → device used by 5 or more other users, rejected
  - **TRIAL-10** trial_payment_timing PASS → first payment 4 days after the trial ended (and one during the trial), allowed
  - **TRIAL-11** trial_payment_timing FAIL → first payment 90 days after the trial ended, no earlier payment, rejected
  - **TRIAL-12** chargeback_history PASS → no chargebacks, allowed
  - **TRIAL-13** chargeback_history FAIL → 2+ chargebacks, requires prepayment
  - **TRIAL-14** device_fingerprint boundaries → 4 other users CHALLENGE; exactly 5 FAIL, even when this user already has the device; a FAIL records no device row
  - **TRIAL-15** trial_payment_timing boundaries → 5 and 89 days after the trial CHALLENGE; 90 days with an earlier payment CHALLENGE
```
