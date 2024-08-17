"""Module used to create functions that help main program"""

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def cert_hash(cert: x509.Certificate):
    """Return certificate hash to compare with signature"""
    return cert.tbs_certificate_bytes


def check_signature_belongs_to_certificate_valid(
    message: bytes, public_key: rsa.RSAPublicKey, signature: bytes
):
    """
    Receives a x509 Certificate and check if signature was signed with the same private key that
    created certificate.
    Return True if certificate was correctly signed, and False if not.
    """
    hash_alg = hashes.SHA256()
    signature_padding = padding.PKCS1v15()

    try:
        public_key.verify(signature, message, signature_padding, hash_alg)
        return True
    except InvalidSignature:
        return False
