import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def init_root(cadir, cn="CertForge Root CA", days=3650):
    cadir = Path(cadir)
    keypath = cadir / "root.key"
    certpath = cadir / "root.pem"
    if keypath.exists() and certpath.exists():
        return

    cadir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CertForge"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(key, hashes.SHA256())
    )

    raw = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(keypath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_root(cadir):
    cadir = Path(cadir)
    key = serialization.load_pem_private_key((cadir / "root.key").read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate((cadir / "root.pem").read_bytes())
    return key, cert


def _san(s):
    try:
        return x509.IPAddress(ipaddress.ip_address(s))
    except ValueError:
        return x509.DNSName(s)


def make_csr(cn, sans=(), org=None):
    key = ec.generate_private_key(ec.SECP256R1())
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([_san(s) for s in sans]), critical=False)
    csr = b.sign(key, hashes.SHA256())
    keypem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return keypem, csr.public_bytes(serialization.Encoding.PEM)


def parse_csr(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError("bad csr signature")

    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn:
        raise ValueError("csr has no common name")
    org = csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)

    sans = []
    try:
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        ext = []
    for name in ext:
        sans.append(str(name.value))

    return {"cn": cn[0].value, "sans": sans, "org": org[0].value if org else None}


def sign_csr(cadir, csr_pem, days=365):
    parse_csr(csr_pem)
    csr = x509.load_pem_x509_csr(csr_pem)
    cakey, cacert = load_root(cadir)
    now = dt.datetime.now(dt.timezone.utc)

    b = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(cacert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://localhost:5000/crl.pem")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]),
            critical=False,
        )
    )
    try:
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        b = b.add_extension(sans, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = b.sign(cakey, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)
