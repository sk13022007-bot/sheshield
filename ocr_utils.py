import io
import os
import re
import hashlib

import pytesseract
import phonenumbers
from phonenumbers import geocoder, carrier
from PIL import Image, ImageOps

_DEFAULT_PATH = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(_DEFAULT_PATH):
    pytesseract.pytesseract.tesseract_cmd = _DEFAULT_PATH

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+\.[A-Za-z.]{2,}")
UPI_RE = re.compile(r"\b[A-Za-z0-9._\-]{2,}@[A-Za-z]{2,}\b(?!\.)")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
HANDLE_RE = re.compile(r"(?<![\w@.])@[A-Za-z0-9_.]{3,30}")


def image_hash(data):
    return hashlib.sha256(data).hexdigest()


def read_text(data):
    img = Image.open(io.BytesIO(data))
    img = ImageOps.exif_transpose(img).convert("L")
    if img.width < 1000:
        img = img.resize((img.width * 2, img.height * 2))
    try:
        text = pytesseract.image_to_string(img, lang="eng+hin+kan")
    except pytesseract.TesseractError:
        # Hindi/Kannada data not installed: fall back to English only
        text = pytesseract.image_to_string(img, lang="eng")
    return text.strip()


def _unique(items):
    seen = set()
    out = []
    for x in items:
        key = x.lower()
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def find_phones(text):
    out = []
    seen = set()
    for m in phonenumbers.PhoneNumberMatcher(text, "IN"):
        n = m.number
        e164 = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
        if e164 in seen:
            continue
        seen.add(e164)
        out.append({
            "number": e164,
            "display": phonenumbers.format_number(
                n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "valid": phonenumbers.is_valid_number(n),
            "region": geocoder.description_for_number(n, "en"),
            "carrier": carrier.name_for_number(n, "en"),
        })
    return out


def extract_identifiers(text):
    emails = _unique(EMAIL_RE.findall(text))
    upi = [u for u in _unique(UPI_RE.findall(text))]
    urls = _unique(URL_RE.findall(text))
    handles = _unique(HANDLE_RE.findall(text))
    return {
        "phones": find_phones(text),
        "emails": emails,
        "upi_ids": upi,
        "urls": urls,
        "handles": handles,
    }