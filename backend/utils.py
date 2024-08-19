"""Module used to create functions that help main program"""
import json

import sqlite3
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

table_name = "user_certificates"

con = sqlite3.connect("data.db")
cur = con.cursor()

def dict_to_bytes(dict_data: dict):
    """Convert python dict to bytes"""
    json_str = json.dumps(dict_data)
    return json_str.encode()

def create_table():
    cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name} (user_id varchar(200), certificate varchar(1800), active bool, public_key varchar(200), due_data date)")

def get_certificate_by_user(user_id: str):
    try:
        cur.execute(f"SELECT * FROM {table_name} WHERE user_id = '{user_id}'")
        row = cur.fetchone()
        return row
    except Exception as e:
        return False

def delete_table():
    try:
        cur.execute(f"DROP TABLE {table_name}")
        return True
    except Exception as e:
        return False

def add_user_certificate(user_id: str, certificate: str):
    try:
        pub_key = get_certificate_pubkey(certificate)
        cur.execute(f"INSERT INTO {table_name} VALUES ({user_id}, {certificate}, true, {pub_key})")
        return True
    except Exception as e:
        return False
    
def update_certificate_status(cert_new_status: bool, user_id: str):
    try:
        sql = 'UPDATE table_name SET active = ? WHERE user_id = ?'
        cur.execute(sql, (cert_new_status, user_id))
        return True
    except:
        return False

def get_certificate_pubkey(cert: str):
    try:
        cert = x509.load_pem_x509_certificate(cert)
        return cert.public_key()
    except Exception as e:
        return None


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
