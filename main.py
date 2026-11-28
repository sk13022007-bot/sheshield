import json
import os
import re
from datetime import datetime, timezone

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import pytesseract

from analyzer import analyze
from ocr_utils import read_text, extract_identifiers, image_hash
from report import build_report
import vault

app = FastAPI(title="SheShield")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

MAX_BYTES = 8 * 1024 * 1024
ANCHOR_FILE = "anchors.json"
TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


class Msg(BaseModel):
    text: str


class ImgEvidence(BaseModel):
    text: str
    image_sha256: str
    identifiers: dict = {}


class AnchorIn(BaseModel):
    tx_hash: str
    vault_hash: str


def _load_anchors():
    if not os.path.exists(ANCHOR_FILE):
        return []
    try:
        with open(ANCHOR_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _latest_vault_hash():
    items = vault.list_all()
    if not items:
        return None
    return max(items, key=lambda i: i.get("id", 0)).get("hash")


@app.get("/")
def home():
    return FileResponse("index.html")


@app.get("/health")
def health():
    return {"app": "SheShield", "status": "running"}


@app.post("/analyze")
def check(m: Msg):
    return analyze(m.text)


@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(400, "Please upload an image file (PNG or JPG).")
    data = await file.read()
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "Image is too large (max 8 MB).")
    try:
        text = read_text(data)
    except pytesseract.TesseractNotFoundError:
        raise HTTPException(
            503, "Tesseract OCR is not installed or not found on this computer.")
    except Exception:
        raise HTTPException(400, "Could not read this image.")
    sha = image_hash(data)
    if not text:
        return {"text": "", "image_sha256": sha, "identifiers": {},
                "analysis": None}
    return {
        "text": text,
        "image_sha256": sha,
        "identifiers": extract_identifiers(text),
        "analysis": analyze(text),
    }


@app.post("/vault")
def save_evidence(m: Msg):
    r = analyze(m.text)
    return vault.add(m.text, r["severity"], r["score"])


@app.post("/vault/image")
def save_image_evidence(e: ImgEvidence):
    r = analyze(e.text)
    parts = [e.text.strip(), "[screenshot sha256: " + e.image_sha256 + "]"]
    ids = []
    for kind, values in e.identifiers.items():
        for v in values:
            if isinstance(v, dict):
                v = v.get("number", "")
            if v:
                ids.append(kind + "=" + str(v))
    if ids:
        parts.append("[identifiers: " + ", ".join(ids) + "]")
    return vault.add("\n".join(parts), r["severity"], r["score"])


@app.get("/vault")
def list_evidence():
    return vault.list_all()


@app.get("/vault/verify")
def verify_evidence():
    return vault.verify_all()


@app.get("/vault/latest-hash")
def latest_hash():
    return {"hash": _latest_vault_hash()}


@app.post("/anchor")
def save_anchor(a: AnchorIn):
    if not TX_RE.match(a.tx_hash):
        raise HTTPException(400, "Invalid transaction hash.")
    anchors = _load_anchors()
    anchors.append({
        "tx_hash": a.tx_hash,
        "vault_hash": a.vault_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    with open(ANCHOR_FILE, "w", encoding="utf-8") as f:
        json.dump(anchors, f)
    return anchors[-1]


@app.get("/anchor")
def get_anchor():
    anchors = _load_anchors()
    return {"anchor": anchors[-1] if anchors else None}


@app.get("/report")
def report():
    anchors = _load_anchors()
    tx = anchors[-1]["tx_hash"] if anchors else None
    pdf = build_report(vault.list_all(), vault.verify_all(), tx)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition":
                 'inline; filename="SheShield_Complaint_Report.pdf"'},
    )