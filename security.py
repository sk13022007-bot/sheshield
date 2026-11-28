"""Cryptography, PIN handling and sessions.

Key design (see README "Security model"):
  * Each account has a random 256-bit data key (DEK). It encrypts that account's evidence
    with AES-256-GCM. The DEK is never stored in the clear.
  * The DEK is stored only in wrapped form, encrypted under a key-encryption key (KEK)
    derived from the user's PIN with Argon2id. A second wrapped copy exists under a
    one-time recovery code, which is shown once and never stored.
  * The unwrapped DEK lives only in server memory while a session is unlocked.
  * The PIN itself is stored only as an Argon2id hash (separate salt from the KEK salt).
Nothing here is hardcoded: all keys come from os.urandom or from the user's secret.
"""
import base64
import hmac
import os
import secrets
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id cost. Tests lower these through configure_kdf(); production keeps the defaults.
KDF = {"time_cost": 3, "memory_cost": 65536, "parallelism": 2}
_hasher = None


def configure_kdf(time_cost=None, memory_cost=None, parallelism=None):
    global _hasher
    if time_cost: KDF["time_cost"] = time_cost
    if memory_cost: KDF["memory_cost"] = memory_cost
    if parallelism: KDF["parallelism"] = parallelism
    _hasher = None


def _ph():
    global _hasher
    if _hasher is None:
        _hasher = PasswordHasher(time_cost=KDF["time_cost"], memory_cost=KDF["memory_cost"],
                                 parallelism=KDF["parallelism"], hash_len=32, salt_len=16)
    return _hasher


MIN_PIN_LEN = 6
MAX_PIN_LEN = 64


def validate_pin(pin: str):
    if not isinstance(pin, str) or not (MIN_PIN_LEN <= len(pin) <= MAX_PIN_LEN):
        raise ValueError(f"PIN must be {MIN_PIN_LEN} to {MAX_PIN_LEN} characters.")
    if len(set(pin)) == 1:
        raise ValueError("PIN cannot be a single repeated character.")
    low = pin.lower()
    common = {"123456", "1234567", "12345678", "123456789", "1234567890", "654321", "000000", "111111", "121212", "123123",
              "password", "password1", "passw0rd", "qwerty", "qwerty123", "iloveyou", "letmein", "abc123", "admin123",
              "sheshield", "welcome1", "india123", "000000000"}
    digits = low.isdigit()
    sequential = digits and (low in "01234567890123456789" or low in "98765432109876543210")
    if low in common or sequential:
        raise ValueError("That PIN is too easy to guess. Choose a different one.")


def hash_pin(pin: str) -> str:
    return _ph().hash(pin)


def verify_pin(stored_hash: str, pin: str) -> bool:
    try:
        return _ph().verify(stored_hash, pin)
    except (VerifyMismatchError, InvalidHashError):
        return False


def derive_kek(secret: str, salt: bytes) -> bytes:
    return hash_secret_raw(secret.encode("utf-8"), salt, time_cost=KDF["time_cost"],
                           memory_cost=KDF["memory_cost"], parallelism=KDF["parallelism"],
                           hash_len=32, type=Type.ID)


def new_dek() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Raises InvalidTag if the data or its associated data was modified."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def wrap_dek(secret: str, dek: bytes, user_label: bytes):
    salt = os.urandom(16)
    return salt, seal(derive_kek(secret, salt), dek, b"dek|" + user_label)


def unwrap_dek(secret: str, salt: bytes, wrapped: bytes, user_label: bytes) -> bytes:
    return unseal(derive_kek(secret, salt), wrapped, b"dek|" + user_label)


def new_recovery_code() -> str:
    raw = base64.b32encode(os.urandom(15)).decode("ascii")  # 120 bits
    return "-".join(raw[i:i + 6] for i in range(0, len(raw), 6))


def normalise_recovery_code(code: str) -> str:
    return "".join(ch for ch in (code or "").upper() if ch.isalnum())


def lockout_seconds(failed: int) -> int:
    """5 free attempts, then 30s, 60s, 2m ... capped at 15 minutes."""
    if failed < 5:
        return 0
    return min(900, 30 * 2 ** (failed - 5))


# ------------------------------------------------------------------ sessions
SESSION_TTL = int(os.environ.get("SHESHIELD_SESSION_MINUTES", "20")) * 60
COOKIE = "sheshield_session"


@dataclass
class Session:
    user_id: int
    username: str
    dek: bytes
    expires: float


_SESSIONS: dict = {}


def _tok_key(token: str) -> str:
    return b64e(hmac.new(b"sheshield-session", token.encode(), "sha256").digest())


def create_session(user_id: int, username: str, dek: bytes) -> str:
    token = secrets.token_urlsafe(32)
    _SESSIONS[_tok_key(token)] = Session(user_id, username, dek, time.time() + SESSION_TTL)
    return token


def get_session(token):
    if not token:
        return None
    s = _SESSIONS.get(_tok_key(token))
    if not s:
        return None
    if s.expires < time.time():
        _SESSIONS.pop(_tok_key(token), None)
        return None
    s.expires = time.time() + SESSION_TTL   # sliding window
    return s


def end_session(token):
    if token:
        _SESSIONS.pop(_tok_key(token), None)


def end_user_sessions(user_id: int):
    for k in [k for k, s in _SESSIONS.items() if s.user_id == user_id]:
        _SESSIONS.pop(k, None)


def clear_all_sessions():
    _SESSIONS.clear()
