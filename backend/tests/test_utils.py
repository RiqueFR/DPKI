"""
Module used to test functions from "utils.py"
"""

import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.utils import check_certificate_valid


def test_valid_signed_cert_return_true():
    valid_cert_data = None
    with open("tests/signed_cert1.pem", "rb") as valid_cert_file:
        valid_cert_data = valid_cert_file.read()
    cert = x509.load_pem_x509_certificate(valid_cert_data)
    assert check_certificate_valid(cert, cert.signature) is True


def test_corrupted_signed_cert_return_false():
    valid_cert_data = None
    with open("tests/invalid_signed_cert2.pem", "rb") as valid_cert_file:
        valid_cert_data = valid_cert_file.read()
    cert = None
    try:
        cert = x509.load_pem_x509_certificate(valid_cert_data)
        assert check_certificate_valid(cert, cert.signature) is False
    except ValueError:
        pass
    # it shows that certificate failed to load because its corrupted
    assert cert is None


def test_invalid_signed_cert_return_false():
    cert_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    sign_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Espirito Santo"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Serra"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
        ]
    )
    # create a certificate and sign it with other private key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(cert_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
        )
        .sign(sign_private_key, hashes.SHA256(), default_backend())
    )

    assert check_certificate_valid(cert, cert.signature) is False
