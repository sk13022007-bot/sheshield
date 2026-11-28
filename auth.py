import os
import re
import sys
import hmac
import time
import base64
import sqlite3
import hashlib
import secrets
import urllib.parse
import urllib.request
from fastapi import APIRouter, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["auth"])
HERE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(HERE, "sheshield_users_v2.db")
SESSION_SECONDS = 7 * 24 * 3600
OTP_VALID_SECONDS = 300
PEPPER = os.getenv("SHESHIELD_PEPPER", "change-me-before-deploy")

TWILIO_SID = os.getenv("TWILIO_SID", "")
TWILIO_TOKEN = os.getenv("TWILIO_TOKEN", "")
TWILIO_FROM = os.getenv("TWILIO_FROM", "")
SMS_ENABLED = bool(TWILIO_SID and TWILIO_TOKEN and TWILIO_FROM)


def db():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone_hash TEXT UNIQUE NOT NULL,
        salt TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        created_at REAL NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at REAL NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS otps(
        phone_hash TEXT PRIMARY KEY, code_hash TEXT NOT NULL,
        expires_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        sent_at REAL NOT NULL, verified INTEGER NOT NULL DEFAULT 0)""")
    con.commit()
    con.close()


init_db()


def normalize_phone(raw: str) -> str:
    p = re.sub(r"[\s\-()]", "", raw)
    if re.fullmatch(r"[6-9]\d{9}", p):
        return "+91" + p
    if re.fullmatch(r"0?[6-9]\d{9}", p):
        return "+91" + p[-10:]
    if re.fullmatch(r"91[6-9]\d{9}", p):
        return "+" + p
    if re.fullmatch(r"\+\d{8,15}", p):
        return p
    raise HTTPException(400, "Enter a valid mobile number.")


def phone_hash(phone: str) -> str:
    return hmac.new(PEPPER.encode(), phone.encode(), hashlib.sha256).hexdigest()


def code_hash(phone: str, code: str) -> str:
    return hmac.new(PEPPER.encode(), f"{phone}:{code}".encode(), hashlib.sha256).hexdigest()


def hash_pw(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), 200_000).hex()


def send_sms(phone: str, text: str):
    url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json"
    data = urllib.parse.urlencode({"To": phone, "From": TWILIO_FROM, "Body": text}).encode()
    req = urllib.request.Request(url, data=data)
    auth = base64.b64encode(f"{TWILIO_SID}:{TWILIO_TOKEN}".encode()).decode()
    req.add_header("Authorization", "Basic " + auth)
    urllib.request.urlopen(req, timeout=15).read()


def new_session(con, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO sessions VALUES (?,?,?)",
                (token, user_id, time.time() + SESSION_SECONDS))
    con.commit()
    return token


class PhoneIn(BaseModel):
    phone: str


class VerifyIn(BaseModel):
    phone: str
    otp: str


class SignupIn(BaseModel):
    phone: str
    otp: str
    password: str


class LoginIn(BaseModel):
    phone: str
    password: str


@router.post("/send-otp")
def send_otp(d: PhoneIn):
    phone = normalize_phone(d.phone)
    ph = phone_hash(phone)
    con = db()
    if con.execute("SELECT 1 FROM users WHERE phone_hash=?", (ph,)).fetchone():
        con.close()
        raise HTTPException(409, "This number is already registered. Please sign in.")
    old = con.execute("SELECT sent_at FROM otps WHERE phone_hash=?", (ph,)).fetchone()
    if old and time.time() - old["sent_at"] < 30:
        con.close()
        raise HTTPException(429, "Please wait 30 seconds before asking for a new OTP.")
    code = f"{secrets.randbelow(1_000_000):06d}"
    con.execute("INSERT OR REPLACE INTO otps VALUES (?,?,?,?,?,?)",
                (ph, code_hash(phone, code), time.time() + OTP_VALID_SECONDS, 0, time.time(), 0))
    con.commit()
    con.close()
    msg = f"Your SheShield OTP is {code}. It is valid for 5 minutes. Do not share it."
    if SMS_ENABLED:
        try:
            send_sms(phone, msg)
        except Exception:
            raise HTTPException(502, "Could not send the SMS. Check the Twilio settings.")
        return {"sent": True, "mode": "sms"}
    print(f"\n[DEMO OTP] {phone} -> {code}\n")
    return {"sent": True, "mode": "demo", "note": "Demo mode: OTP is shown in the server window."}


def check_otp(con, phone: str, otp: str):
    ph = phone_hash(phone)
    row = con.execute("SELECT * FROM otps WHERE phone_hash=?", (ph,)).fetchone()
    if not row or row["expires_at"] < time.time():
        raise HTTPException(400, "OTP expired. Please request a new one.")
    if row["attempts"] >= 5:
        raise HTTPException(429, "Too many wrong attempts. Request a new OTP.")
    if not hmac.compare_digest(row["code_hash"], code_hash(phone, otp.strip())):
        con.execute("UPDATE otps SET attempts=attempts+1 WHERE phone_hash=?", (ph,))
        con.commit()
        raise HTTPException(400, "Wrong OTP.")
    return ph


@router.post("/verify-otp")
def verify_otp(d: VerifyIn):
    phone = normalize_phone(d.phone)
    con = db()
    ph = check_otp(con, phone, d.otp)
    con.execute("UPDATE otps SET verified=1 WHERE phone_hash=?", (ph,))
    con.commit()
    con.close()
    return {"verified": True}


@router.post("/signup")
def signup(d: SignupIn):
    phone = normalize_phone(d.phone)
    if len(d.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    con = db()
    ph = check_otp(con, phone, d.otp)
    if con.execute("SELECT 1 FROM users WHERE phone_hash=?", (ph,)).fetchone():
        con.close()
        raise HTTPException(409, "This number is already registered. Please sign in.")
    salt = secrets.token_hex(16)
    cur = con.execute(
        "INSERT INTO users(phone_hash, salt, pw_hash, created_at) VALUES (?,?,?,?)",
        (ph, salt, hash_pw(d.password, salt), time.time()))
    con.execute("DELETE FROM otps WHERE phone_hash=?", (ph,))
    con.commit()
    token = new_session(con, cur.lastrowid)
    con.close()
    return {"token": token}


@router.post("/login")
def login(d: LoginIn):
    phone = normalize_phone(d.phone)
    con = db()
    row = con.execute("SELECT * FROM users WHERE phone_hash=?", (phone_hash(phone),)).fetchone()
    if not row or not hmac.compare_digest(row["pw_hash"], hash_pw(d.password, row["salt"])):
        con.close()
        raise HTTPException(401, "Wrong mobile number or password.")
    token = new_session(con, row["id"])
    con.close()
    return {"token": token}


def get_current_user(authorization: str = Header(default="")):
    token = authorization.replace("Bearer ", "").strip()
    con = db()
    row = con.execute(
        """SELECT u.id FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token=? AND s.expires_at>?""", (token, time.time())).fetchone()
    con.close()
    if not row:
        raise HTTPException(401, "Please sign in.")
    return {"id": row["id"]}


@router.get("/me")
def me(authorization: str = Header(default="")):
    get_current_user(authorization)
    return {"signed_in": True}


@router.post("/logout")
def logout(authorization: str = Header(default="")):
    token = authorization.replace("Bearer ", "").strip()
    con = db()
    con.execute("DELETE FROM sessions WHERE token=?", (token,))
    con.commit()
    con.close()
    return {"ok": True}


@router.get("/page", include_in_schema=False)
def login_page():
    with open(os.path.join(HERE, "login.html"), "r", encoding="utf-8", errors="replace") as f:
        return HTMLResponse(f.read())


@router.get("/check", include_in_schema=False)
def check():
    out = {
        "python": sys.version.split()[0],
        "login_html_found": os.path.exists(os.path.join(HERE, "login.html")),
        "folder": HERE,
    }
    try:
        con = db()
        con.execute("SELECT COUNT(*) FROM users").fetchone()
        con.execute("SELECT COUNT(*) FROM otps").fetchone()
        con.close()
        out["database"] = "ok"
    except Exception as e:
        out["database"] = "error: " + str(e)
    return out