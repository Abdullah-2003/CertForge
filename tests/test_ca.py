import datetime as dt
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certforge import ca


@pytest.fixture
def cadir(tmp_path):
    ca.init_root(tmp_path)
    return tmp_path


def test_root_is_ca(cadir):
    key, cert = ca.load_root(cadir)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert bc.ca and bc.path_length == 0
    assert ku.key_cert_sign and ku.crl_sign
    assert cert.issuer == cert.subject
    assert key.public_key() == cert.public_key()
    cert.verify_directly_issued_by(cert)


def test_init_root_twice_keeps_root(cadir):
    before = (cadir / "root.pem").read_bytes()
    ca.init_root(cadir)
    assert (cadir / "root.pem").read_bytes() == before


def test_csr_round_trip():
    _, csr = ca.make_csr("demo.local", ["demo.local", "www.demo.local", "127.0.0.1"], org="Lab")
    assert ca.parse_csr(csr) == {
        "cn": "demo.local",
        "sans": ["demo.local", "www.demo.local", "127.0.0.1"],
        "org": "Lab",
    }


def test_csr_ip_san_is_ip():
    _, csr = ca.make_csr("x", ["10.0.0.1"])
    ext = x509.load_pem_x509_csr(csr).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ext.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("10.0.0.1")]


def test_csr_key_matches():
    key, csr = ca.make_csr("x")
    k = serialization.load_pem_private_key(key, password=None)
    assert k.public_key() == x509.load_pem_x509_csr(csr).public_key()


def test_parse_rejects_junk():
    with pytest.raises(ValueError):
        ca.parse_csr(b"not a csr")


def test_parse_rejects_bad_signature():
    _, csr = ca.make_csr("demo.local")
    der = bytearray(x509.load_pem_x509_csr(csr).public_bytes(serialization.Encoding.DER))
    der[-5] ^= 1
    pem = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(ValueError):
        ca.parse_csr(pem)


def test_parse_rejects_no_cn():
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lab")]))
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(ValueError):
        ca.parse_csr(csr.public_bytes(serialization.Encoding.PEM))


def test_sign_csr(cadir):
    _, csr = ca.make_csr("demo.local", ["demo.local", "127.0.0.1"])
    cert = x509.load_pem_x509_certificate(ca.sign_csr(cadir, csr, days=30))
    _, root = ca.load_root(cadir)

    cert.verify_directly_issued_by(root)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "demo.local"
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(n.value) for n in sans] == ["demo.local", "127.0.0.1"]
    dp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert dp[0].full_name[0].value == "http://localhost:5000/crl.pem"

    life = cert.not_valid_after_utc - dt.datetime.now(dt.timezone.utc)
    assert dt.timedelta(days=29) < life <= dt.timedelta(days=30)


def test_sign_without_sans(cadir):
    _, csr = ca.make_csr("bare")
    cert = x509.load_pem_x509_certificate(ca.sign_csr(cadir, csr))
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_serials_differ(cadir):
    _, csr = ca.make_csr("x")
    a = x509.load_pem_x509_certificate(ca.sign_csr(cadir, csr))
    b = x509.load_pem_x509_certificate(ca.sign_csr(cadir, csr))
    assert a.serial_number != b.serial_number


def test_sign_rejects_junk(cadir):
    with pytest.raises(ValueError):
        ca.sign_csr(cadir, b"junk")
