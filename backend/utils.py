import base64

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def check_certificate_valid(signed_certificate):
    cert = None
    try:
        cert = x509.load_pem_x509_certificate(signed_certificate)
    except ValueError:
        return False

    public_key = cert.public_key()
    signature = cert.signature
    tbs_certificate_bytes = cert.tbs_certificate_bytes
    hash_alg = cert.signature_hash_algorithm
    cert_padding = padding.PKCS1v15()
    try:
        cert_padding = cert.signature_algorithm_parameters
    except AttributeError:
        pass

    try:
        public_key.verify(signature, tbs_certificate_bytes, cert_padding, hash_alg)
        return True
    except InvalidSignature:
        return False
