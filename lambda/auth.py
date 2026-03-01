"""lambda/auth.py — Authentication: register, login, logout, change-pin.

Architecture #7: login() takes explicit event parameter (no __event__ hack).
PDC-03: brute-force lockout after 5 failures.
PDC-18: logout sets valid_after to invalidate all other sessions.
"""
import re
import secrets
from datetime import datetime, timezone, timedelta

from helpers import (
    ok, err, _to_py, hash_pin, verify_pin,
    get_session, users_table, sessions_table,
    DEFAULT_PREFS, SESSION_TTL_HOURS,
    LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_MINUTES,
)
from logging_utils import _log_auth_event


def register(body):
    email = (body.get("email") or "").strip().lower()
    pin   = str(body.get("pin") or "").strip()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return err("Invalid email address.")
    if not re.match(r'^\d{4}$', pin):
        return err("PIN must be exactly 4 digits.")
    if users_table.get_item(Key={"email": email}).get("Item"):
        return err("An account with that email already exists.", 409)
    prefs = {**DEFAULT_PREFS, "notify_email": email}
    users_table.put_item(Item={
        "email":      email,
        "pin_hash":   hash_pin(pin),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "prefs":      prefs,
    })
    return ok({"message": "Account created. Please log in."}, 201)


def login(event, body):
    """Architecture #7: takes explicit event instead of body['__event__'] hack."""
    email = (body.get("email") or "").strip().lower()
    pin   = str(body.get("pin") or "").strip()
    now   = datetime.now(timezone.utc)

    user = users_table.get_item(Key={"email": email}).get("Item")

    # Timing-safe: always run verify_pin even when user not found
    if not user:
        verify_pin(pin, "")
        _log_auth_event(event, email, False, "bad_pin")
        return err("Invalid email or PIN.", 401)

    user = _to_py(user)

    # ── Check lockout ──────────────────────────────────────────────
    lockout_until_str = user.get("lockout_until", "")
    if lockout_until_str:
        try:
            lockout_until = datetime.fromisoformat(lockout_until_str)
            if lockout_until.tzinfo is None:
                lockout_until = lockout_until.replace(tzinfo=timezone.utc)
            if now < lockout_until:
                remaining_secs = int((lockout_until - now).total_seconds())
                remaining_mins = max(1, (remaining_secs + 59) // 60)
                _log_auth_event(event, email, False, "locked_out")
                return err(
                    f"Account locked. Try again in {remaining_mins} minute{'s' if remaining_mins != 1 else ''}.",
                    429,
                    _extra={"locked_until": lockout_until.isoformat(),
                            "retry_after_seconds": remaining_secs}
                )
        except Exception as e:
            print(f"[PDC] lockout parse error: {e}")

    # ── Verify PIN ─────────────────────────────────────────────────
    pin_ok = verify_pin(pin, user.get("pin_hash", ""))

    if not pin_ok:
        attempts    = int(user.get("failed_attempts", 0)) + 1
        update_expr = "SET failed_attempts = :a, last_failed_at = :t"
        expr_vals   = {":a": attempts, ":t": now.isoformat()}

        if attempts >= LOGIN_MAX_ATTEMPTS:
            lockout_until = now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
            update_expr  += ", lockout_until = :lu"
            expr_vals[":lu"] = lockout_until.isoformat()
            users_table.update_item(
                Key={"email": email},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_vals,
            )
            _log_auth_event(event, email, False, "locked_out")
            return err(
                f"Too many failed attempts. Account locked for {LOGIN_LOCKOUT_MINUTES} minutes.",
                429,
                _extra={"locked_until": lockout_until.isoformat()},
            )

        users_table.update_item(
            Key={"email": email},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_vals,
        )
        remaining = LOGIN_MAX_ATTEMPTS - attempts
        _log_auth_event(event, email, False, "bad_pin")
        return err(
            f"Invalid email or PIN. {remaining} attempt{'s' if remaining != 1 else ''} remaining before lockout.",
            401,
        )

    # ── Success — clear lockout state ──────────────────────────────
    users_table.update_item(
        Key={"email": email},
        UpdateExpression="REMOVE failed_attempts, lockout_until, last_failed_at",
    )
    token      = secrets.token_hex(32)
    expires_at = int((now + timedelta(hours=SESSION_TTL_HOURS)).timestamp())
    sessions_table.put_item(Item={
        "token":              token,
        "email":              email,
        "expires_at":         expires_at,
        "session_created_at": int(now.timestamp()),
    })
    _log_auth_event(event, email, True)
    prefs = _to_py(user.get("prefs", DEFAULT_PREFS))
    if not prefs.get("notify_email"):
        prefs["notify_email"] = email
    return ok({"token": token, "email": email, "prefs": prefs})


def logout(event):
    """PDC-18: delete current session and set valid_after to reject all older tokens."""
    sess = get_session(event)
    if sess:
        sessions_table.delete_item(Key={"token": sess.get("token", "")})
        try:
            users_table.update_item(
                Key={"email": sess["email"]},
                UpdateExpression="SET valid_after = :t",
                ExpressionAttributeValues={":t": int(datetime.now(timezone.utc).timestamp())},
            )
        except Exception as e:
            print(f"[PDC] logout valid_after update failed: {e}")
    return ok({"message": "Logged out."})


def change_pin(event, body):
    sess = get_session(event)
    if not sess: return err("Not authenticated.", 401)
    current_pin = str(body.get("current_pin") or "").strip()
    new_pin     = str(body.get("new_pin") or "").strip()
    if not re.match(r'^\d{4}$', new_pin): return err("New PIN must be 4 digits.")
    user = users_table.get_item(Key={"email": sess["email"]}).get("Item")
    if not user or not verify_pin(current_pin, user.get("pin_hash", "")):
        return err("Current PIN is incorrect.", 401)
    users_table.update_item(
        Key={"email": sess["email"]},
        UpdateExpression="SET pin_hash = :p",
        ExpressionAttributeValues={":p": hash_pin(new_pin)},
    )
    return ok({"message": "PIN updated."})
