from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
import pytesseract

from analyzer import analyze
from ocr_utils import read_text, extract_identifiers, image_hash
from report import build_report
import vault

app = FastAPI(title="SheShield")

MAX_BYTES = 8 * 1024 * 1024


class Msg(BaseModel):
    text: str


class ImgEvidence(BaseModel):
    text: str
    image_sha256: str
    identifiers: dict = {}


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


@app.get("/report")
def report():
    pdf = build_report(vault.list_all(), vault.verify_all())
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition":
                 'inline; filename="SheShield_Complaint_Report.pdf"'},
    )