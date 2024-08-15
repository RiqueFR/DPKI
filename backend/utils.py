import base64

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def check_certificate_valid(certificate):
    public_key = certificate.public_key()
    signature = certificate.signature
    certificate_bytes = certificate.tbs_certificate_bytes

    hash_alg = certificate.signature_hash_algorithm
    cert_padding = padding.PKCS1v15()
    try:
        cert_padding = certificate.signature_algorithm_parameters
    except AttributeError:
        pass

    try:
        public_key.verify(signature, certificate_bytes, cert_padding, hash_alg)
        return True
    except InvalidSignature:
        return False
