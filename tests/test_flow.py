import flask
import pytest
from cryptography import x509

from certforge import ca, db, web


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(flask.Flask, "auto_find_instance_path", lambda self: str(tmp_path))
    return web.create_app({"TESTING": True, "ADMIN_PASSWORD": "pw"})


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    client.get("/verify")
    with client.session_transaction() as s:
        return s["csrf"]


def login(client, pw="pw"):
    client.get("/admin/login")
    with client.session_transaction() as s:
        tok = s["csrf"]
    res = client.post("/admin/login", data={"csrf": tok, "password": pw})
    with client.session_transaction() as s:
        return res, s["csrf"]


def submit(client, cn="demo.local", sans="demo.local 127.0.0.1"):
    tok = csrf(client)
    res = client.post("/request", data={"csrf": tok, "mode": "generate", "cn": cn, "sans": sans})
    assert res.status_code == 302
    with client.session_transaction() as s:
        return s["request_id"]


def approve(client, rid):
    _, tok = login(client)
    res = client.post(f"/admin/approve/{rid}", data={"csrf": tok})
    assert res.status_code == 302


def serial_for(app, rid):
    with app.app_context():
        return db.get_db().execute("SELECT serial FROM certs WHERE request_id = ?", (rid,)).fetchone()["serial"]


def check(client, pem):
    return client.post("/verify", data={"csrf": csrf(client), "cert": pem}).get_data(as_text=True)


def test_full_lifecycle(app, client):
    rid = submit(client)
    login(client)
    assert "demo.local" in client.get("/admin").get_data(as_text=True)

    approve(client, rid)
    serial = serial_for(app, rid)

    page = client.get("/").get_data(as_text=True)
    assert "demo.local" in page and "valid" in page

    pem = client.get(f"/certs/{serial}.pem").data
    cert = x509.load_pem_x509_certificate(pem)
    root = x509.load_pem_x509_certificate(client.get("/root.pem").data)
    cert.verify_directly_issued_by(root)
    assert "<strong>Valid.</strong>" in check(client, pem)

    tok = csrf(client)
    res = client.post(f"/admin/revoke/{serial}", data={"csrf": tok, "reason": "keyCompromise"})
    assert res.status_code == 302

    crl = x509.load_pem_x509_crl(client.get("/crl.pem").data)
    assert crl.get_revoked_certificate_by_serial_number(int(serial, 16)) is not None
    assert crl.is_signature_valid(root.public_key())

    res = check(client, pem)
    assert "Not valid." in res and "revoked" in res
    assert "revoked" in client.get(f"/certs/{serial}").get_data(as_text=True).lower()


def test_admin_needs_login(client):
    res = client.get("/admin")
    assert res.status_code == 302 and "/admin/login" in res.headers["Location"]


def test_wrong_password(client):
    res, _ = login(client, "nope")
    assert res.status_code == 401
    assert client.get("/admin").status_code == 302


def test_post_without_csrf(app, client):
    rid = submit(client)
    login(client)
    assert client.post(f"/admin/approve/{rid}", data={}).status_code == 400


def test_reject_then_approve_conflicts(client):
    rid = submit(client)
    _, tok = login(client)
    assert client.post(f"/admin/reject/{rid}", data={"csrf": tok}).status_code == 302
    assert client.post(f"/admin/approve/{rid}", data={"csrf": tok}).status_code == 409


def test_bad_pasted_csr(client):
    res = client.post("/request", data={"csrf": csrf(client), "mode": "paste", "csr": "garbage"})
    assert res.status_code == 400


def test_pasted_csr(app, client):
    _, csr = ca.make_csr("pasted.local", ["pasted.local"])
    res = client.post("/request", data={"csrf": csrf(client), "mode": "paste", "csr": csr.decode()})
    assert res.status_code == 302
    with client.session_transaction() as s:
        rid = s["request_id"]
    approve(client, rid)
    assert "pasted.local" in client.get("/").get_data(as_text=True)


def test_key_downloads_once(client):
    submit(client)
    tok = csrf(client)
    first = client.post("/request/key", data={"csrf": tok})
    assert first.status_code == 200 and b"PRIVATE KEY" in first.data
    assert client.post("/request/key", data={"csrf": tok}).status_code == 404


def test_verify_foreign_cert(client, tmp_path):
    other = tmp_path / "other"
    ca.init_root(other)
    _, csr = ca.make_csr("evil.local")
    pem = ca.sign_csr(other, csr)
    assert "chain" in check(client, pem.decode()).lower()


def test_verify_expired(app, client, tmp_path):
    _, csr = ca.make_csr("old.local")
    pem = ca.sign_csr(tmp_path / "ca", csr, days=0)
    assert "expired" in check(client, pem.decode()).lower()
