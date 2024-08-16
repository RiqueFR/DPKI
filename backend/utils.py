"""Module used to create functions that help main program"""

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding


def check_certificate_valid(certificate: x509.Certificate, signature: bytes):
    """
    Receives a x509 Certificate and check if signature was signed with the same private key that
    created certificate.
    Return True if certificate was correctly signed, and False if not.
    """
    public_key = certificate.public_key()
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
