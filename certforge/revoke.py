import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import ca


def status(row, now=None):
    if row["revoked_at"]:
        return "revoked"

    now = now or dt.datetime.now(dt.timezone.utc)
    not_after = dt.datetime.fromisoformat(row["not_after"])
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=dt.timezone.utc)

    if now > not_after:
        return "expired"
    return "valid"


def revoke(conn, serial, reason="unspecified"):
    now = dt.datetime.now(dt.timezone.utc)
    with conn:
        result = conn.execute(
            "UPDATE certs SET revoked_at = ?, revoke_reason = ? WHERE serial = ? AND revoked_at IS NULL",
            (now.isoformat(), reason, serial),
        )
    if result.rowcount != 1:
        raise ValueError("certificate not found or already revoked")


def build_crl(cadir, conn):
    cadir = Path(cadir)
    cakey, cacert = ca.load_root(cadir)
    now = dt.datetime.now(dt.timezone.utc)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(cacert.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=7))
    )
    for row in conn.execute("SELECT serial, revoked_at FROM certs WHERE revoked_at IS NOT NULL"):
        revoked_at = dt.datetime.fromisoformat(row["revoked_at"])
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(row["serial"], 16))
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)

    crl = builder.sign(cakey, hashes.SHA256())
    pem = crl.public_bytes(serialization.Encoding.PEM)
    (cadir / "crl.pem").write_bytes(pem)
    return pem


def verify(cadir, conn, cert_pem):
    cadir = Path(cadir)
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError:
        return False, "not a valid certificate"

    _, cacert = ca.load_root(cadir)
    try:
        cacert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm)
        )
    except (InvalidSignature, TypeError, ValueError):
        return False, "signature does not chain to the CertForge root"

    now = dt.datetime.now(dt.timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, "not yet valid"
    if now > cert.not_valid_after_utc:
        return False, "expired"

    crl_path = cadir / "crl.pem"
    if crl_path.exists():
        crl = x509.load_pem_x509_crl(crl_path.read_bytes())
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
            return False, "revoked"

    return True, "ok"
