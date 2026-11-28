"""Optional voice-note transcription with faster-whisper, run LOCALLY on this server.

Audio is written to a temp file only for the duration of transcription, then deleted.
Nothing is sent to an external service by this module. The first run downloads the model weights
(internet needed once); after that it works offline.
"""
import os
import tempfile

MAX_BYTES = 15 * 1024 * 1024
ALLOWED = {".wav", ".mp3", ".m4a", ".ogg", ".webm", ".flac", ".aac", ".opus"}
_model = None


def status():
    try:
        import faster_whisper  # noqa
        return {"available": True, "model": os.environ.get("SHESHIELD_WHISPER_MODEL", "base"), "where": "local"}
    except Exception:
        return {"available": False, "where": "local",
                "reason": "Voice transcription is optional and not installed. Run: pip install faster-whisper"}


def _get_model():
    global _model
    if _model is None:
        from faster_whisper import WhisperModel
        _model = WhisperModel(os.environ.get("SHESHIELD_WHISPER_MODEL", "base"), device="cpu", compute_type="int8")
    return _model


def transcribe(data: bytes, filename: str, language: str | None = None):
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in ALLOWED:
        raise ValueError("Unsupported audio type. Use WAV, MP3, M4A, OGG, WEBM, FLAC or AAC.")
    if len(data) > MAX_BYTES:
        raise ValueError("Audio is too large (max 15 MB).")
    if not status()["available"]:
        raise RuntimeError(status()["reason"])
    fd, path = tempfile.mkstemp(suffix=ext)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        segments, info = _get_model().transcribe(path, language=language or None, vad_filter=True)
        text = " ".join(s.text.strip() for s in segments).strip()
        return {"text": text, "language": info.language, "language_probability": round(float(info.language_probability), 2)}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
