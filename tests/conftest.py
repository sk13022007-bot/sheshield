import os, sys, tempfile
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("SHESHIELD_DB", os.path.join(tempfile.mkdtemp(), "t.db"))
import security
security.configure_kdf(1, 8192, 1)   # cheap Argon2 for tests only


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SHESHIELD_DB", str(tmp_path / "t.db"))
    security.clear_all_sessions()
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)


PIN = "Zx83!kp2-orchid"


def register(c, name="alice", pin=PIN):
    r = c.post("/auth/register", json={"username": name, "pin": pin})
    assert r.status_code == 200, r.text
    return r.json()
