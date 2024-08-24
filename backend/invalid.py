import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

cert_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
with open("tests/privkey3_cert.pem", "wb") as priv_file:
    priv_file.write(
        cert_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
sign_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
with open("tests/privkey3_sign.pem", "wb") as priv_file:
    priv_file.write(
        sign_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
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
with open("tests/invalid_signed_cert3.pem", "wb") as cert_file:
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
