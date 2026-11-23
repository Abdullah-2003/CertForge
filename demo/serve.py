import argparse
import datetime as dt
import http.server
import sqlite3
import ssl
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509

from certforge import ca

INSTANCE = ROOT / "instance"
CADIR = INSTANCE / "ca"
DBPATH = INSTANCE / "certforge.db"

PAGE = b"""<!doctype html>
<html><body>
<h1>CertForge demo server</h1>
<p>If your browser shows this page without a warning, it trusted a certificate
issued by the CertForge root CA.</p>
</body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, fmt, *args):
        pass


def issue_demo_cert(cn):
    keypath = INSTANCE / "demo.key"
    certpath = INSTANCE / "demo.pem"

    conn = sqlite3.connect(DBPATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT pem FROM certs WHERE cn = ? AND revoked_at IS NULL ORDER BY not_before DESC LIMIT 1",
        (cn,),
    ).fetchone()
    if row is not None and keypath.exists():
        conn.close()
        return keypath, certpath

    key, csr = ca.make_csr(cn, sans=[cn, "127.0.0.1"])
    cert_pem = ca.sign_csr(CADIR, csr)
    cert = x509.load_pem_x509_certificate(cert_pem)
    conn.execute(
        "INSERT INTO certs (serial, request_id, cn, issuer, not_before, not_after, pem) "
        "VALUES (?, NULL, ?, ?, ?, ?, ?)",
        (format(cert.serial_number, "x"), cn, cert.issuer.rfc4514_string(),
         cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat(), cert_pem.decode()),
    )
    conn.commit()
    conn.close()

    keypath.write_bytes(key)
    certpath.write_bytes(cert_pem)
    return keypath, certpath


def make_self_signed(cn):
    keypath = INSTANCE / "demo-selfsigned.key"
    certpath = INSTANCE / "demo-selfsigned.pem"
    if keypath.exists() and certpath.exists():
        return keypath, certpath

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    keypath.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return keypath, certpath


def main():
    parser = argparse.ArgumentParser(description="CertForge HTTPS demo server")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cn", default="localhost")
    parser.add_argument(
        "--self-signed", action="store_true",
        help="serve an unknown self-signed certificate instead of one issued by CertForge",
    )
    args = parser.parse_args()

    if not CADIR.exists() or not DBPATH.exists():
        sys.exit("run the main CertForge app once first (python run.py) so the root CA and database exist")

    if args.self_signed:
        keypath, certpath = make_self_signed(args.cn)
        print("serving an UNKNOWN self-signed certificate (not issued by CertForge)")
    else:
        keypath, certpath = issue_demo_cert(args.cn)
        print(f"serving a certificate issued by the CertForge root for cn={args.cn}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(certpath), keyfile=str(keypath))

    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"https://localhost:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
