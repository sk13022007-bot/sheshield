# SheShield

Check a threatening message or screenshot, keep tamper-evident evidence, optionally anchor a fingerprint on the Ethereum Sepolia testnet, and generate a complaint report PDF.

## Run locally

```bash
python -m venv venv
venv\Scripts\activate          # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open http://127.0.0.1:8000. Screenshot reading needs [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) installed (with Hindi and Kannada data for those languages).

## Layout

- `main.py`, `analyzer.py`, `vault.py`, `ocr_utils.py`, `report.py`: backend (API unchanged)
- `index.html`: page structure and icon set
- `static/style.css`: design system (colours, type, components)
- `static/app.js`: all front-end behaviour, wallet and blockchain verification
- `static/fonts/`: Fraunces and Instrument Sans, bundled so the app works offline
- `tamper.py`: demo tool. `python tamper.py 1` edits record 1 so you can watch the vault flag it; `python tamper.py restore` undoes it

Set your contract address at the top of `static/app.js` (`ANCHOR_CONTRACT`).
