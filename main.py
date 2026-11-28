"""SheShield API. Every data endpoint requires an unlocked vault session (httpOnly cookie)."""
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import pytesseract

import auth
import contacts
import db
import emergency
import identifiers
import insights
import legal
import security as sec
import vault
import voice
from analyzer import analyze
from ocr_utils import read_text, extract_identifiers, image_hash
from report import build_report

app = FastAPI(title="SheShield")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

MAX_BYTES = 8 * 1024 * 1024
MAX_TEXT = 10000
TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SECURE_COOKIE = os.environ.get("SHESHIELD_COOKIE_SECURE") == "1"


# ---------------------------------------------------------------- plumbing
@app.exception_handler(auth.AuthError)
async def _auth_err(_, e: auth.AuthError):
    h = {"Retry-After": str(e.retry_after)} if getattr(e, "retry_after", None) else {}
    return JSONResponse({"detail": e.message}, status_code=e.status, headers=h)


@app.exception_handler(contacts.ContactError)
async def _contact_err(_, e: contacts.ContactError):
    return JSONResponse({"detail": e.message}, status_code=e.status)


@app.middleware("http")
async def _guard(request: Request, call_next):
    # CSRF defence in depth (cookie is SameSite=Strict): refuse cross-origin state-changing requests.
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        if origin:
            host = request.headers.get("host", "")
            if urlparse(origin).netloc != host:
                return JSONResponse({"detail": "Cross-origin request refused."}, status_code=403)
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith(("/auth", "/vault", "/report", "/intel", "/legal", "/insights", "/contacts", "/anchor")):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def require_user(request: Request) -> sec.Session:
    s = sec.get_session(request.cookies.get(sec.COOKIE))
    if not s:
        raise HTTPException(401, "Your vault is locked. Unlock it to continue.")
    return s


def _set_cookie(resp, token):
    resp.set_cookie(sec.COOKIE, token, httponly=True, samesite="strict", secure=SECURE_COOKIE,
                    max_age=sec.SESSION_TTL, path="/")


class Msg(BaseModel):
    text: str = Field(max_length=MAX_TEXT)


class ImgEvidence(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    image_sha256: str
    identifiers: dict = {}


class Creds(BaseModel):
    username: str
    pin: str


class Register(Creds):
    claim_legacy: bool = False


class ChangePin(BaseModel):
    old_pin: str
    new_pin: str


class Recover(BaseModel):
    username: str
    recovery_code: str
    new_pin: str


class Wipe(BaseModel):
    pin: str
    confirm: str


class AnchorIn(BaseModel):
    tx_hash: str
    vault_hash: str
    mode: str = "legacy"            # legacy | contract
    chain_id: str | None = None
    contract: str | None = None


class AnchorState(BaseModel):
    tx_hash: str
    state: str                       # confirmed | verified | mismatch
    detail: str | None = None


class ContactIn(BaseModel):
    name: str
    email: str
    sender_name: str = ""


class CodeIn(BaseModel):
    code: str


class AlertPrep(BaseModel):
    evidence_id: int | None = None


class AlertConfirm(BaseModel):
    confirm_token: str


# ---------------------------------------------------------------- pages / health / config
@app.get("/")
def home():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/health")
def health():
    return {"app": "SheShield", "status": "running"}


@app.get("/config")
def config():
    """Public, non-secret configuration for the browser. Never returns keys."""
    addr = os.environ.get("SHESHIELD_CONTRACT_ADDRESS", "")
    abi = None
    p = os.path.join(BASE_DIR, "contracts", "SheShieldAnchor.abi.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            abi = json.load(f)
    return {
        "chain_id": os.environ.get("SHESHIELD_CHAIN_ID", "0xaa36a7"),
        "network": "Sepolia test network",
        "contract_address": addr if ADDR_RE.match(addr) else None,
        "abi": abi,
        "explorer": "https://sepolia.etherscan.io",
        "smtp_configured": contacts.smtp_configured(),
        "voice": voice.status(),
        "session_minutes": sec.SESSION_TTL // 60,
    }


# ---------------------------------------------------------------- auth
@app.get("/auth/status")
def auth_status(request: Request):
    s = sec.get_session(request.cookies.get(sec.COOKIE))
    return {"authenticated": bool(s), "username": s.username if s else None,
            "has_accounts": auth.user_count() > 0, "legacy_available": auth.legacy_available(),
            "session_minutes": sec.SESSION_TTL // 60, "pin_rules": f"{sec.MIN_PIN_LEN}-{sec.MAX_PIN_LEN} characters; avoid repeated or common PINs"}


@app.post("/auth/register")
def auth_register(b: Register):
    uid, code, dek = auth.register(b.username, b.pin, b.claim_legacy)
    uname = auth.clean_username(b.username)
    token = sec.create_session(uid, uname, dek)
    resp = JSONResponse({"username": uname, "recovery_code": code,
                         "recovery_note": "Shown once. Write it down and keep it somewhere safe. If you forget your PIN, this code is the only way back in. Nobody, including SheShield, can reset it for you."})
    _set_cookie(resp, token)
    return resp


@app.post("/auth/login")
def auth_login(b: Creds):
    uid, uname, dek = auth.login(b.username, b.pin)
    token = sec.create_session(uid, uname, dek)
    resp = JSONResponse({"username": uname})
    _set_cookie(resp, token)
    return resp


@app.post("/auth/logout")
def auth_logout(request: Request):
    sec.end_session(request.cookies.get(sec.COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(sec.COOKIE, path="/")
    return resp


@app.post("/auth/change-pin")
def auth_change_pin(b: ChangePin, s: sec.Session = Depends(require_user)):
    auth.change_pin(s.user_id, s.username, b.old_pin, b.new_pin)
    return {"ok": True}


@app.post("/auth/recover")
def auth_recover(b: Recover):
    uid, uname, dek = auth.recover(b.username, b.recovery_code, b.new_pin)
    token = sec.create_session(uid, uname, dek)
    resp = JSONResponse({"username": uname})
    _set_cookie(resp, token)
    return resp


@app.post("/auth/wipe")
def auth_wipe(b: Wipe, s: sec.Session = Depends(require_user)):
    """Panic wipe. Requires the PIN and the exact phrase. Deletes this account's data on this server."""
    if b.confirm != "DELETE MY VAULT":
        raise HTTPException(400, 'Type DELETE MY VAULT exactly to confirm.')
    auth.login(s.username, b.pin)  # re-checks PIN, applies lockout rules
    counts = auth.wipe_user(s.user_id)
    resp = JSONResponse({"wiped": counts, "not_erased": [
        "Blockchain transactions you submitted. They are permanent and public, but contain only a fingerprint, not your evidence.",
        "PDF reports, screenshots or files you saved or shared elsewhere.",
        "Anything your trusted contact or an email provider already received.",
        "Copies on your device's own backups or in browser history.",
        "Image fingerprints stored locally in this browser (clear them in Emergency Support)."]})
    resp.delete_cookie(sec.COOKIE, path="/")
    return resp


# ---------------------------------------------------------------- analysis
def _prior_categories(user_id):
    c = db.connect()
    try:
        rows = c.execute("SELECT category FROM analysis_log WHERE user_id=? AND category!='benign' ORDER BY id DESC LIMIT 5", (user_id,)).fetchall()
        return [r["category"] for r in rows]
    finally:
        c.close()


def _log_analysis(user_id, r, source):
    c = db.connect()
    try:
        c.execute("INSERT INTO analysis_log (user_id, created_at, category, severity, score, language, source) VALUES (?,?,?,?,?,?,?)",
                  (user_id, datetime.now(timezone.utc).isoformat(), r["category"], r["severity"], r["score"], r["language"], source))
        c.commit()
    finally:
        c.close()


def _run(user_id, text, source):
    r = analyze(text, {"prior_categories": _prior_categories(user_id)})
    _log_analysis(user_id, r, source)
    return r


def _meta_from(r, ids, source, extra=None):
    m = {"category": r["category"], "language": r["language"], "confidence": r["confidence"], "source": source,
         "indicators": r["indicators"], "identifiers": ids}
    m.update(extra or {})
    return m


@app.post("/analyze")
def check(m: Msg, s: sec.Session = Depends(require_user)):
    r = _run(s.user_id, m.text, "text")
    r["identifiers"] = identifiers.from_extracted(extract_identifiers(m.text), "typed")
    return r


@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...), s: sec.Session = Depends(require_user)):
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(400, "Please upload an image file (PNG or JPG).")
    data = await file.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "Image is too large (max 8 MB).")
    try:
        text = read_text(data)
    except pytesseract.TesseractNotFoundError:
        raise HTTPException(503, "Tesseract OCR is not installed or not found on this computer.")
    except Exception:
        raise HTTPException(400, "Could not read this image.")
    sha = image_hash(data)
    if not text:
        return {"text": "", "image_sha256": sha, "identifiers": {}, "analysis": None}
    ex = extract_identifiers(text)
    r = _run(s.user_id, text, "image")
    return {"text": text, "image_sha256": sha, "identifiers": ex, "analysis": r}


@app.get("/voice/status")
def voice_status(_: sec.Session = Depends(require_user)):
    return voice.status()


@app.post("/transcribe")
async def transcribe(file: UploadFile = File(...), consent: str = Form(""), language: str = Form(""),
                     s: sec.Session = Depends(require_user)):
    """Transcribe a voice note locally, then run the transcript through the normal pipeline."""
    if consent != "yes":
        raise HTTPException(400, "Please confirm you agree to transcribe this audio before continuing.")
    st = voice.status()
    if not st["available"]:
        raise HTTPException(503, st["reason"])
    data = await file.read()
    try:
        t = voice.transcribe(data, file.filename or "", language or None)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        raise HTTPException(500, "Transcription failed. The audio may be unreadable.")
    del data
    if not t["text"]:
        return {"transcript": "", "language": t["language"], "analysis": None, "note": "No speech was detected."}
    r = _run(s.user_id, t["text"], "voice")
    return {"transcript": t["text"], "language": t["language"], "language_probability": t["language_probability"],
            "analysis": r, "identifiers": identifiers.from_extracted(extract_identifiers(t["text"]), "typed"),
            "note": "Transcripts can contain mistakes. Check it against the recording before saving."}


# ---------------------------------------------------------------- vault
@app.post("/vault")
def save_evidence(m: Msg, s: sec.Session = Depends(require_user)):
    r = _run(s.user_id, m.text, "text")
    ids = identifiers.from_extracted(extract_identifiers(m.text), "typed")
    rec = vault.add(s, m.text, r["severity"], r["score"], _meta_from(r, ids, "text"))
    rec["analysis"] = r
    return rec


@app.post("/vault/transcript")
def save_transcript(m: Msg, s: sec.Session = Depends(require_user)):
    """Save a (user-checked) voice transcript. Audio itself is never stored."""
    r = _run(s.user_id, m.text, "voice")
    ids = identifiers.from_extracted(extract_identifiers(m.text), "typed")
    rec = vault.add(s, "[voice-note transcript]\n" + m.text, r["severity"], r["score"], _meta_from(r, ids, "voice"))
    rec["analysis"] = r
    return rec


@app.post("/vault/image")
def save_image_evidence(e: ImgEvidence, s: sec.Session = Depends(require_user)):
    if not HASH_RE.match(e.image_sha256):
        raise HTTPException(400, "Invalid image fingerprint.")
    r = _run(s.user_id, e.text, "image")
    ids = identifiers.from_extracted(e.identifiers, "ocr")
    parts = [e.text.strip(), "[screenshot sha256: " + e.image_sha256 + "]"]
    if ids:
        parts.append("[identifiers: " + ", ".join(f"{i['kind']}={i['raw']}" for i in ids) + "]")
    rec = vault.add(s, "\n".join(parts), r["severity"], r["score"], _meta_from(r, ids, "image", {"image_sha256": e.image_sha256}))
    rec["analysis"] = r
    return rec


@app.get("/vault")
def list_evidence(s: sec.Session = Depends(require_user)):
    return vault.list_all(s)


@app.get("/vault/verify")
def verify_evidence(s: sec.Session = Depends(require_user)):
    return vault.verify_all(s)


@app.get("/vault/latest-hash")
def latest_hash(s: sec.Session = Depends(require_user)):
    return {"hash": vault.latest_hash(s)}


# ---------------------------------------------------------------- intelligence / legal / emergency
@app.get("/intel/links")
def intel_links(s: sec.Session = Depends(require_user)):
    return identifiers.link_records(vault.list_all(s))


def _pathway_for(s, evidence_id=None, category=None):
    items = vault.list_all(s)
    rec = None
    if evidence_id is not None:
        rec = next((i for i in items if i["id"] == evidence_id), None)
        if not rec:
            raise HTTPException(404, "That evidence record was not found in your vault.")
    elif category is None and items:
        rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
        rec = max(items, key=lambda i: (rank.get(i["severity"], 0), i["id"]))
    meta = (rec or {}).get("meta") or {}
    cat = category or meta.get("category")
    if cat == "benign":
        cat = None
    summary = None
    if rec:
        summary = f"Record #{rec['id']} saved {rec['created_at']} was classed by automated analysis as {cat or 'no specific category'} (risk {rec['severity']})."
    p = legal.pathway(cat, [i.get("label") for i in meta.get("indicators", [])], summary)
    p["evidence_id"] = rec["id"] if rec else None
    return p


@app.get("/legal/pathway")
def legal_pathway(evidence_id: int | None = None, category: str | None = None, s: sec.Session = Depends(require_user)):
    return _pathway_for(s, evidence_id, category)


@app.get("/emergency/guide")
def emergency_guide(_: sec.Session = Depends(require_user)):
    return emergency.guide()


@app.get("/insights")
def get_insights(s: sec.Session = Depends(require_user)):
    return insights.compute(s)


# ---------------------------------------------------------------- trusted contact
@app.get("/contacts")
def contact_get(s: sec.Session = Depends(require_user)):
    d = contacts.get(s)
    d["history"] = contacts.history(s)
    return d


@app.post("/contacts")
def contact_add(b: ContactIn, s: sec.Session = Depends(require_user)):
    return contacts.add(s, b.name, b.email, b.sender_name)


@app.post("/contacts/verify")
def contact_verify(b: CodeIn, s: sec.Session = Depends(require_user)):
    return contacts.verify(s, b.code)


@app.delete("/contacts")
def contact_remove(s: sec.Session = Depends(require_user)):
    return contacts.remove(s)


@app.post("/contacts/alert/prepare")
def alert_prepare(b: AlertPrep, s: sec.Session = Depends(require_user)):
    items = vault.list_all(s)
    if not items:
        raise HTTPException(409, "Save at least one piece of evidence first. The alert refers to an evidence fingerprint.")
    rec = next((i for i in items if i["id"] == b.evidence_id), None) if b.evidence_id else items[-1]
    if not rec:
        raise HTTPException(404, "That evidence record was not found in your vault.")
    return contacts.prepare_alert(s, rec)


@app.post("/contacts/alert/send")
def alert_send(b: AlertConfirm, s: sec.Session = Depends(require_user)):
    return contacts.send_alert(s, b.confirm_token)


@app.post("/contacts/alert/cancel")
def alert_cancel(b: AlertConfirm, s: sec.Session = Depends(require_user)):
    return contacts.cancel_alert(s, b.confirm_token)


# ---------------------------------------------------------------- blockchain anchors
def _anchor_row(r):
    return {"tx_hash": r["tx_hash"], "vault_hash": r["vault_hash"], "created_at": r["created_at"], "mode": r["mode"],
            "chain_id": r["chain_id"], "contract": r["contract"], "state": r["state"] if "state" in r.keys() else "submitted"}


@app.post("/anchor")
def save_anchor(a: AnchorIn, s: sec.Session = Depends(require_user)):
    if not TX_RE.match(a.tx_hash):
        raise HTTPException(400, "Invalid transaction hash.")
    if not HASH_RE.match(a.vault_hash):
        raise HTTPException(400, "Invalid vault hash.")
    if a.mode not in ("legacy", "contract"):
        raise HTTPException(400, "Invalid anchor mode.")
    if a.contract and not ADDR_RE.match(a.contract):
        raise HTTPException(400, "Invalid contract address.")
    if a.vault_hash != vault.latest_hash(s):
        raise HTTPException(409, "The vault changed since this fingerprint was created. Anchor the current fingerprint.")
    c = db.connect()
    try:
        c.execute("INSERT INTO anchors (user_id, tx_hash, vault_hash, created_at, mode, chain_id, contract, state) VALUES (?,?,?,?,?,?,?,?)",
                  (s.user_id, a.tx_hash, a.vault_hash, datetime.now(timezone.utc).isoformat(), a.mode, a.chain_id, a.contract, "submitted"))
        c.commit()
        return _anchor_row(c.execute("SELECT * FROM anchors WHERE user_id=? ORDER BY id DESC LIMIT 1", (s.user_id,)).fetchone())
    finally:
        c.close()


@app.post("/anchor/state")
def set_anchor_state(a: AnchorState, s: sec.Session = Depends(require_user)):
    """The browser reports what it observed on-chain. Stored so the PDF can state it honestly."""
    if not TX_RE.match(a.tx_hash) or a.state not in ("confirmed", "verified", "mismatch"):
        raise HTTPException(400, "Invalid anchor state.")
    c = db.connect()
    try:
        n = c.execute("UPDATE anchors SET state=? WHERE user_id=? AND tx_hash=?", (a.state, s.user_id, a.tx_hash)).rowcount
        c.commit()
    finally:
        c.close()
    if not n:
        raise HTTPException(404, "No such anchor in your vault.")
    return {"ok": True}


@app.get("/anchor")
def get_anchor(s: sec.Session = Depends(require_user)):
    c = db.connect()
    try:
        rows = c.execute("SELECT * FROM anchors WHERE user_id=? ORDER BY id DESC LIMIT 20", (s.user_id,)).fetchall()
        hist = [_anchor_row(r) for r in rows]
    finally:
        c.close()
    return {"anchor": hist[0] if hist else None, "history": hist, "current_vault_hash": vault.latest_hash(s)}


@app.get("/report")
def report(evidence_id: int | None = None, s: sec.Session = Depends(require_user)):
    items = vault.list_all(s)
    integ = vault.verify_all(s)
    a = get_anchor(s)["anchor"]
    pw = _pathway_for(s, evidence_id) if items else None
    links = identifiers.link_records(items) if items else None
    pdf = build_report(items, integ, a, pw, links)
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'inline; filename="SheShield_Complaint_Report.pdf"'})
