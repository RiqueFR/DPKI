"""Module used to create functions that help main program"""

import json
import os
import sqlite3


from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from db_handler import DB


def add_user_certificate(db: DB, user_id: str, certificate: x509.Certificate):
    public_key = certificate.public_key()
    public_key_hex = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()
    certificate_hex = certificate.public_bytes(serialization.Encoding.PEM).hex()
    due_date = certificate.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
    return db.add_user_certificate(user_id, certificate_hex, public_key_hex, due_date)


def update_certificate_status(db: DB, user_id: str, cert_new_status: bool):
    return db.update_certificate_status(user_id, cert_new_status)


def dict_to_bytes(dict_data: dict):
    """Convert python dict to bytes"""
    json_str = json.dumps(dict_data)
    return json_str.encode()


def sign_message(message: bytes, private_key_path: str, signature_out_path: str):
    """Save signed message to signature_out_path"""
    privkey_data = None
    with open(private_key_path, "rb") as privkey_file:
        privkey_data = privkey_file.read()
    private_key = serialization.load_pem_private_key(privkey_data, password=None)

    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    with open(signature_out_path, "wb") as signature_file:
        signature_file.write(signature)


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
