import base64

from cryptography import x509
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
    padding = cert.signature_algorithm_parameters

    try:
        public_key.verify(signature, tbs_certificate_bytes, padding, hash_alg)
        return True
    except InvalidSignature:
        return False
