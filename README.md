# SheShield

A private evidence tool for people facing online harassment, blackmail or sextortion. It checks messages, keeps encrypted tamper-evident evidence, shows reporting options and possibly relevant laws, and can build a PDF for the police.

**It is not a lawyer, not a police service and not a verdict.** Results are indicators about message wording, never findings about a person.

## Run it

```bash
# Windows: double-click run.bat      macOS/Linux: ./run.sh
# or manually:
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```
Open **http://127.0.0.1:8000**. Opening `index.html` directly does not work (the app needs its server); a banner says so.

Screenshot reading needs the **Tesseract OCR** program installed (with Hindi and Kannada language data for those scripts).

First visit: create a vault name and PIN, and **write down the recovery code** shown once. There is no other way to recover a forgotten PIN.

**Upgrading from the earlier unauthenticated version:** every endpoint now needs an unlocked vault (API clients must log in via `POST /auth/login` and keep the cookie). When you create the first vault you can tick "move earlier evidence into this vault"; old rows keep valid hashes and become encrypted. The old `anchors.json` file is not migrated (it referred to a different contract).

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `SHESHIELD_DB` | SQLite file path | `vault.db` |
| `SHESHIELD_SESSION_MINUTES` | inactivity auto-lock | `20` |
| `SHESHIELD_COOKIE_SECURE` | set `1` when served over HTTPS | off |
| `SHESHIELD_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` | email for trusted-contact codes and alerts | unset (feature disabled, honestly reported) |
| `SHESHIELD_SMTP_STARTTLS` / `_SSL` | `1`/`0`; STARTTLS defaults on | `1` / off |
| `SHESHIELD_CONTRACT_ADDRESS` | deployed `SheShieldAnchor` address | unset (anchoring disabled) |
| `SHESHIELD_CHAIN_ID` | chain id hex | `0xaa36a7` (Sepolia) |
| `SHESHIELD_WHISPER_MODEL` | faster-whisper model size | `base` |
| `SHESHIELD_PDF_FONT` | path to a TTF covering Hindi/Kannada for the PDF (Windows uses Nirmala automatically) | unset |
| `SEPOLIA_RPC_URL`, `DEPLOYER_PRIVATE_KEY` | **deployment script only**; use a throwaway test wallet | unset |

No secret is stored in the repository. `.env`, `*.db` and deployment output are git-ignored.

## Features

- **Check a message** (text, screenshot, optional voice note): category, risk, confidence, language, indicators, explanation, next steps.
- **Evidence vault**: per-user, AES-256-GCM encrypted, SHA-256 hash-chained, tamper detection.
- **Incident intelligence**: repeated phone / email / UPI / handle / link detection **inside your own vault**, with timeline and cautions (recycled numbers, shared devices, OCR errors).
- **Legal action & reporting**: potentially relevant BNS 2023 and IT Act 2000 provisions with reasons and conditions, plus reporting channels. Provisions last checked 2026-11-28 against indiacode and secondary sources; verify current text before relying on them.
- **Emergency support** for sextortion, with a local image-fingerprint prototype (see limits).
- **Trusted contact**: verified by emailed code; alert is previewed, confirmed, cancellable.
- **Reports**: PDF with incident summary, a "Your Next Steps – Reporting & Legal Pathway" section, provisions, channels, repeated identifiers, evidence hashes, integrity and blockchain state.
- **Safety insights**: statistics of your own vault only.
- **Settings & privacy**: change PIN, lock, discreet mode, panic wipe.

## Security model

- PIN → Argon2id → key that wraps a random 256-bit data key; records are sealed with AES-256-GCM, bound to the user and record time. The server stores only the wrapped key and a PIN hash. A second wrapping under the recovery code allows recovery.
- Sessions: random token in an httpOnly, SameSite=Strict cookie; the unwrapped key lives only in server memory and expires after inactivity or lock. Cross-origin writes are refused.
- Lockout: 5 wrong PINs, then 30 s doubling up to 15 min.
- **Not encrypted:** record id, time, risk level, score and hashes (needed to verify the chain without unlocking everything).
- **Does not protect against** malware or someone using your unlocked computer, or the server operator reading memory while you are logged in. Run SheShield on a computer you control.
- **Panic wipe** deletes the account's rows and keys and runs `VACUUM`. It cannot erase blockchain transactions, exported PDFs, screenshots, emails already sent, OS backups or browser history. The UI says so.
- **Discreet mode** only changes the tab title, icon and brand text and adds Esc-Esc quick exit. It does not hide history or that the program runs.

## Blockchain (Sepolia)

Contract: `contracts/SheShieldAnchor.sol` (compiled ABI/bytecode in `contracts/`). It stores only a 32-byte fingerprint, sender and time. `anchor(bytes32)` reverts on duplicates; `getAnchor(bytes32)` reads it back.

```bash
export SEPOLIA_RPC_URL=https://...          # any Sepolia RPC
export DEPLOYER_PRIVATE_KEY=0x...           # TEST wallet with Sepolia ETH only
python scripts/deploy_sepolia.py            # prints the address, refuses other chains
export SHESHIELD_CONTRACT_ADDRESS=0x...     # then restart the app
```
Anchor from the **Blockchain proof** page with MetaMask. Four states are kept distinct: **stored locally** → **submitted** (tx hash from wallet) → **confirmed** (receipt read: mined, succeeded, sent to the contract) → **verified** (fingerprint read back from the contract via `eth_call`, found in your vault, and vault integrity passes). Verification without a wallet: `python scripts/verify_anchor.py <hash>`.
The contract is **not deployed by this package** (that needs your wallet); until you deploy it, the page says anchoring is unavailable. Contract logic is tested on an in-memory EVM (`tests/test_contract.py`). The live Sepolia flow with MetaMask was **not** tested here.

## AI model

`python train_model.py` rebuilds `threat_model.joblib`, `ml/metrics.json` and `MODEL_CARD.md`. The dataset is **synthetic and template-based** (666 messages from 242 templates; English, Hinglish, Hindi, Kannada, Kanglish), split by template so no template crosses splits. Held-out results are modest (model alone: accuracy 0.46, macro-F1 0.44); the rules carry most of the detection. Details and per-category/language tables are in `MODEL_CARD.md`. Real-world accuracy is unmeasured; Hindi and Kannada text needs native-speaker review.

Voice: `pip install faster-whisper`. Transcription runs locally; audio is held in a temp file only while transcribing; only the transcript can be saved, with consent.

## Tests

```bash
pytest tests -q                    # 36 tests: auth, lockout, encryption, tamper, isolation, wipe, legal, linking, PDF, contacts, contract
python tamper.py 2 && python tamper.py restore   # manual tamper demo
```

## Not implemented / limits

- **Cross-user matching is intentionally not built.** It would need consent and privacy-preserving protocols; matching is per-vault only.
- The image fingerprint tool is a **local prototype**: it contacts nothing and blocks nothing. Use StopNCII.org for real blocking.
- Alerts report "accepted by mail server", never "delivered" or "read".
- OCR can misread digits; identifier matches from screenshots carry a caution.
- PDF Indian-script text needs a suitable font on non-Windows systems (`SHESHIELD_PDF_FONT`).
- Legal text is informational and must be checked against current official sources.
