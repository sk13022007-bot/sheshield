import json, os, re, sqlite3, time
import pytest
from conftest import register, PIN
import security, identifiers, legal
from analyzer import analyze

SX = "send 10000 rupees or i will post your nude photos on instagram tonight"


# ---------- auth / access control
def test_endpoints_require_login(client):
    for m, p in [("get", "/vault"), ("get", "/vault/verify"), ("get", "/report"), ("get", "/intel/links"), ("get", "/legal/pathway"),
                 ("get", "/insights"), ("get", "/contacts"), ("get", "/anchor"), ("get", "/emergency/guide")]:
        assert getattr(client, m)(p).status_code == 401, p
    assert client.post("/analyze", json={"text": "x"}).status_code == 401
    assert client.post("/vault", json={"text": "x"}).status_code == 401


def test_register_login_logout(client):
    j = register(client)
    assert re.match(r"^[A-Z0-9-]{20,}$", j["recovery_code"])
    assert client.get("/vault").status_code == 200
    client.post("/auth/logout")
    assert client.get("/vault").status_code == 401
    assert client.post("/auth/login", json={"username": "alice", "pin": PIN}).status_code == 200


def test_weak_pins_rejected(client):
    for pin in ["111111", "123456", "abc", "password"]:
        assert client.post("/auth/register", json={"username": "bob", "pin": pin}).status_code == 400


def test_lockout_after_failed_attempts(client):
    register(client); client.post("/auth/logout")
    codes = [client.post("/auth/login", json={"username": "alice", "pin": "wrong-pin-x"}).status_code for _ in range(6)]
    assert codes[:4] == [401] * 4 and codes[4] == 429
    r = client.post("/auth/login", json={"username": "alice", "pin": PIN})
    assert r.status_code == 429 and "Retry-After" in r.headers          # correct PIN also blocked while locked


def test_generic_login_error_for_unknown_user(client):
    r = client.post("/auth/login", json={"username": "nobody", "pin": "whatever1"})
    assert r.status_code == 401 and "Incorrect vault name or PIN" in r.json()["detail"]


def test_cookie_flags(client):
    r = client.post("/auth/register", json={"username": "alice", "pin": PIN})
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc


def test_cross_origin_post_refused(client):
    r = client.post("/auth/login", json={"username": "a", "pin": "b"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_session_expiry(client, monkeypatch):
    register(client)
    for s in security._SESSIONS.values():
        s.expires = time.time() - 1
    assert client.get("/vault").status_code == 401


def test_change_pin_and_recovery(client):
    j = register(client)
    client.post("/vault", json={"text": SX})
    assert client.post("/auth/change-pin", json={"old_pin": "wrong", "new_pin": "New-Pin-9921"}).status_code == 401
    assert client.post("/auth/change-pin", json={"old_pin": PIN, "new_pin": "New-Pin-9921"}).status_code == 200
    client.post("/auth/logout")
    assert client.post("/auth/login", json={"username": "alice", "pin": PIN}).status_code == 401
    assert client.post("/auth/login", json={"username": "alice", "pin": "New-Pin-9921"}).status_code == 200
    client.post("/auth/logout")
    r = client.post("/auth/recover", json={"username": "alice", "recovery_code": j["recovery_code"], "new_pin": "Third-Pin-5530"})
    assert r.status_code == 200
    assert len(client.get("/vault").json()) == 1          # data still decrypts after recovery
    client.post("/auth/logout")
    assert client.post("/auth/recover", json={"username": "alice", "recovery_code": "AAAA-BBBB-CCCC-DDDD-EEEE", "new_pin": "Fourth-Pin-1"}).status_code == 401


# ---------- encryption, integrity, tamper detection
def _db(client):
    return sqlite3.connect(os.environ["SHESHIELD_DB"])


def test_content_encrypted_at_rest(client):
    register(client)
    client.post("/vault", json={"text": SX + " scam@okaxis"})
    raw = " ".join(str(x) for row in _db(client).execute("SELECT content, meta FROM evidence") for x in row)
    assert "nude" not in raw and "okaxis" not in raw and "instagram" not in raw


def test_tamper_detected_and_restored(client):
    register(client)
    for t in ["hello there", SX, "see you"]:
        client.post("/vault", json={"text": t})
    assert client.get("/vault/verify").json() == {"ok": True, "items_checked": 3}
    con = _db(client); orig = con.execute("SELECT content FROM evidence WHERE id=2").fetchone()[0]
    con.execute("UPDATE evidence SET content=? WHERE id=2", (("A" if orig[0] != "A" else "B") + orig[1:],)); con.commit()
    v = client.get("/vault/verify").json()
    assert v["ok"] is False and v["tampered_at_id"] == 2
    con.execute("UPDATE evidence SET content=? WHERE id=2", (orig,)); con.commit()
    assert client.get("/vault/verify").json()["ok"] is True


def test_hash_chain_edit_of_severity_not_hidden_and_swap_detected(client):
    register(client)
    client.post("/vault", json={"text": "first one"}); client.post("/vault", json={"text": SX})
    con = _db(client)
    a, b = [r[0] for r in con.execute("SELECT content FROM evidence ORDER BY id")]
    con.execute("UPDATE evidence SET content=? WHERE id=1", (b,)); con.execute("UPDATE evidence SET content=? WHERE id=2", (a,)); con.commit()
    assert client.get("/vault/verify").json()["ok"] is False        # swapping ciphertexts fails authentication


def test_users_cannot_see_each_others_data(client):
    register(client, "alice"); client.post("/vault", json={"text": "alice secret " + SX}); client.post("/auth/logout")
    register(client, "bobby", "Other-Pin-4410")
    assert client.get("/vault").json() == []
    client.post("/vault", json={"text": "bob note"})
    assert [i["id"] for i in client.get("/vault").json()] == [2]
    assert "alice" not in json.dumps(client.get("/vault").json()) and client.get("/vault/verify").json()["items_checked"] == 1
    assert client.get("/legal/pathway?evidence_id=1").status_code == 404   # alice's record id is not reachable
    client.post("/auth/logout"); client.post("/auth/login", json={"username": "alice", "pin": PIN})
    assert len(client.get("/vault").json()) == 1


def test_wrong_key_cannot_decrypt(client):
    register(client); client.post("/vault", json={"text": SX})
    import vault
    ctx = security.Session(1, "alice", os.urandom(32), time.time() + 100)
    assert vault.list_all(ctx)[0]["readable"] is False


# ---------- panic wipe
def test_wipe_requires_pin_and_phrase_and_erases(client):
    register(client); client.post("/vault", json={"text": SX})
    assert client.post("/auth/wipe", json={"pin": PIN, "confirm": "yes"}).status_code == 400
    assert client.post("/auth/wipe", json={"pin": "wrongwrong", "confirm": "DELETE MY VAULT"}).status_code == 401
    r = client.post("/auth/wipe", json={"pin": PIN, "confirm": "DELETE MY VAULT"})
    assert r.status_code == 200 and r.json()["wiped"]["evidence"] == 1 and any("Blockchain" in x for x in r.json()["not_erased"])
    assert client.get("/vault").status_code == 401
    assert client.post("/auth/login", json={"username": "alice", "pin": PIN}).status_code == 401
    assert _db(client).execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 0


# ---------- analysis, legal, links
def test_analysis_core_cases():
    assert analyze(SX)["category"] == "sextortion" and analyze(SX)["emergency"]["sextortion"]
    assert analyze("see you at college tomorrow")["category"] == "benign"
    assert analyze("i will kill it at the interview tomorrow!")["category"] == "benign"
    assert analyze("tujhe jaan se maar dunga")["category"] == "threat"
    assert analyze("तेरे फोटो वायरल कर दूँगा")["category"] == "sextortion"
    assert analyze("your account will be suspended. share otp now")["category"] == "phishing"
    r = analyze(SX); assert r["indicators"] and r["explanation"] and r["next_steps"] and r["confidence"] in ("low", "medium", "high")


def test_language_detection():
    from analyzer import detect_language as d
    assert d("hello how are you") == "en" and d("तुझे जान से मार दूँगा") == "hi" and d("ನಿನ್ನ ಫೋಟೋ ಕಳಿಸು") == "kn"
    assert d("mera paise de warna kal") == "hinglish" and d("naanu ninna mane ide naale") == "kanglish"


def test_legal_pathway_content():
    p = legal.pathway("sextortion", ["x"])
    refs = " ".join(x["ref"] for x in p["provisions"])
    assert "66E" in refs and "Section 308" in refs and "67A" in refs
    blob = json.dumps(p)
    assert "IPC" not in blob and "Indian Penal Code" not in blob and "not legal advice" in blob.lower()
    ids = [c["id"] for c in p["channels"]]
    assert "emergency" in ids and "ncrp" in ids and "fraud_1930" not in ids      # 1930 only for financial fraud
    assert "fraud_1930" in [c["id"] for c in legal.pathway("financial_scam")["channels"]]
    assert all(x["status"].startswith("Potentially applicable") for x in p["provisions"])
    assert legal.pathway(None)["provisions"] == []


def test_identifier_normalisation():
    n = identifiers.normalise
    assert n("phone", "098450 12345") == n("phone", "+91 98450-12345") == "+919845012345"
    assert n("upi", "Scam@OKAXIS") == "scam@okaxis" and n("email", " A@B.com ") == "a@b.com"
    assert n("phone", "12") is None


def test_identifier_linking_end_to_end(client):
    register(client)
    client.post("/vault", json={"text": SX + " pay scam@okaxis"})
    client.post("/vault", json={"text": "hello, nothing here"})
    client.post("/vault", json={"text": "pay again scam@OKAXIS or photos viral"})
    d = client.get("/intel/links").json()
    g = d["groups"][0]
    assert g["headline"] == "Repeated identifier detected" and g["message"] == "This UPI ID appears in 2 evidence records in this vault."
    assert g["record_ids"] == [1, 3] and g["cautions"] and "offender" not in json.dumps(d).replace("never labels anyone as an offender", "")
    assert d["clusters"][0]["record_ids"] == [1, 3]


def test_ocr_flagged_cautions():
    recs = [{"id": i, "created_at": f"2026-11-0{i}T10:00:00+00:00", "severity": "low", "meta": {"identifiers": [{"kind": "phone", "value": "+919845012345", "source": "ocr"}]}} for i in (1, 2)]
    g = identifiers.link_records(recs)["groups"][0]
    assert any("reading error" in c for c in g["cautions"]) and any("recycled" in c.lower() for c in g["cautions"])


def test_report_pdf_has_required_sections(client):
    register(client); client.post("/vault", json={"text": SX + " scam@okaxis"})
    r = client.get("/report"); assert r.status_code == 200 and r.content[:4] == b"%PDF"
    from pypdf import PdfReader
    import io
    txt = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(r.content)).pages)
    for k in ["Your Next Steps", "Reporting & Legal Pathway", "66E", "Section 308", "cybercrime.gov.in", "not legal advice", "Vault check", "Not anchored"]:
        assert k in txt, k
    assert "IPC" not in txt


def test_anchor_states_and_validation(client):
    register(client); client.post("/vault", json={"text": SX})
    h = client.get("/vault/latest-hash").json()["hash"]; tx = "0x" + "ab" * 32
    assert client.post("/anchor", json={"tx_hash": "bad", "vault_hash": h}).status_code == 400
    assert client.post("/anchor", json={"tx_hash": tx, "vault_hash": "0" * 64}).status_code == 409   # not the current vault hash
    a = client.post("/anchor", json={"tx_hash": tx, "vault_hash": h, "mode": "contract", "contract": "0x" + "1" * 40}).json()
    assert a["state"] == "submitted"
    assert client.post("/anchor/state", json={"tx_hash": tx, "state": "verified"}).status_code == 200
    assert client.get("/anchor").json()["anchor"]["state"] == "verified"
    assert client.post("/anchor/state", json={"tx_hash": tx, "state": "bogus"}).status_code == 400
    from pypdf import PdfReader; import io
    assert "read back from the contract" in " ".join(p.extract_text() for p in PdfReader(io.BytesIO(client.get("/report").content)).pages).replace("\n", " ")


def test_anchors_are_per_user(client):
    register(client, "alice"); client.post("/vault", json={"text": SX}); h = client.get("/vault/latest-hash").json()["hash"]
    client.post("/anchor", json={"tx_hash": "0x" + "cd" * 32, "vault_hash": h}); client.post("/auth/logout")
    register(client, "bobby", "Other-Pin-4410"); assert client.get("/anchor").json()["anchor"] is None


def test_insights_local_and_honest(client):
    register(client); client.post("/analyze", json={"text": SX}); client.post("/vault", json={"text": "see you tomorrow"})
    d = client.get("/insights").json()
    assert d["total_analysed"] == 2 and d["total_saved"] == 1 and d["integrity"]["percent_verified"] == 100.0
    assert "own vault" in d["scope"] and len(d["trend_30d"]) == 30


def test_input_validation(client):
    register(client)
    assert client.post("/analyze", json={"text": "x" * 10001}).status_code == 422
    assert client.post("/vault/image", json={"text": "t", "image_sha256": "zz", "identifiers": {}}).status_code == 400
    assert client.post("/analyze-image", files={"file": ("a.txt", b"hi", "text/plain")}).status_code == 400
    assert client.post("/transcribe", files={"file": ("a.wav", b"x", "audio/wav")}, data={"consent": ""}).status_code == 400


def test_voice_requires_consent_and_degrades(client):
    register(client)
    r = client.post("/transcribe", files={"file": ("a.wav", b"x", "audio/wav")}, data={"consent": "yes"})
    assert r.status_code in (503, 400, 500)   # 503 if faster-whisper is not installed


# ---------- trusted contact (uses a local SMTP sink)
@pytest.fixture()
def smtp(monkeypatch):
    aiosmtpd = pytest.importorskip("aiosmtpd.controller")
    box = []

    class H:
        async def handle_DATA(self, server, session, envelope):
            box.append(envelope.content.decode()); return "250 OK"
    c = aiosmtpd.Controller(H(), hostname="127.0.0.1", port=8026); c.start()
    monkeypatch.setenv("SHESHIELD_SMTP_HOST", "127.0.0.1"); monkeypatch.setenv("SHESHIELD_SMTP_PORT", "8026"); monkeypatch.setenv("SHESHIELD_SMTP_STARTTLS", "0")
    yield box
    c.stop()


def test_contact_requires_smtp(client, monkeypatch):
    monkeypatch.delenv("SHESHIELD_SMTP_HOST", raising=False)
    register(client)
    assert client.post("/contacts", json={"name": "M", "email": "m@example.org"}).status_code == 503


def test_contact_flow_confirmation_and_minimal_message(client, smtp):
    register(client); client.post("/vault", json={"text": SX + " scam@okaxis +919845012345"})
    assert client.post("/contacts/alert/prepare", json={}).status_code == 409           # no verified contact yet
    assert client.post("/contacts", json={"name": "Meera", "email": "not-an-email"}).status_code == 400
    assert client.post("/contacts", json={"name": "Meera", "email": "meera@example.org", "sender_name": "Asha"}).status_code == 200
    code = re.search(r"code is: (\d{6})", smtp[-1]).group(1)
    assert client.post("/contacts/verify", json={"code": "000000" if code != "000000" else "111111"}).status_code == 400
    assert client.post("/contacts/verify", json={"code": code}).json()["verified"] is True
    n = len(smtp)
    prep = client.post("/contacts/alert/prepare", json={}).json()
    assert len(smtp) == n                                  # preparing sends nothing
    for bad in ("nude", "okaxis", "9845012345", "instagram"):
        assert bad not in prep["message"]
    assert re.search(r"[0-9a-f]{64}", prep["message"]) and "HIGH" in prep["message"]
    client.post("/contacts/alert/cancel", json={"confirm_token": prep["confirm_token"]})
    assert client.post("/contacts/alert/send", json={"confirm_token": prep["confirm_token"]}).status_code == 410   # cancelled token is dead
    assert len(smtp) == n
    prep = client.post("/contacts/alert/prepare", json={}).json()
    r = client.post("/contacts/alert/send", json={"confirm_token": prep["confirm_token"]}).json()
    assert r["status"] == "accepted_by_mail_server" and len(smtp) == n + 1
    assert client.post("/contacts/alert/send", json={"confirm_token": prep["confirm_token"]}).status_code == 410   # single use
    assert client.get("/contacts").json()["history"][0]["status"] == "accepted_by_mail_server"


def test_contact_code_attempt_limit(client, smtp):
    register(client); client.post("/contacts", json={"name": "M", "email": "m@example.org"})
    for _ in range(5):
        client.post("/contacts/verify", json={"code": "000001"})
    assert client.post("/contacts/verify", json={"code": "000001"}).status_code == 410


def test_other_user_cannot_use_my_confirm_token(client, smtp):
    register(client, "alice"); client.post("/vault", json={"text": SX})
    client.post("/contacts", json={"name": "M", "email": "m@example.org"}); code = re.search(r"code is: (\d{6})", smtp[-1]).group(1)
    client.post("/contacts/verify", json={"code": code}); tok = client.post("/contacts/alert/prepare", json={}).json()["confirm_token"]
    client.post("/auth/logout"); register(client, "bobby", "Other-Pin-4410")
    assert client.post("/contacts/alert/send", json={"confirm_token": tok}).status_code == 410


def test_no_secrets_in_config(client):
    j = json.dumps(client.get("/config").json()).lower()
    assert "private" not in j and "password" not in j and "key" not in j.replace("keys", "")
