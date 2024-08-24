import json
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from utils import dict_to_bytes, sign_message

""" 
Create a message to send on the blockchain 
Only create and revoke operation supported!
"""

if len(sys.argv) != 4:
    print(
        """Usage: python create_message.py <private_key_path> <operation> <certificate_path/name>

Operation types are "create" or "update"
Use "certificate_path" for create operation and "name" for revoke operation"""
    )
    sys.exit(1)
private_key_path = sys.argv[1]
operation = sys.argv[2]
message_dict = None

if operation == "create":
    cert_path = sys.argv[3]
    cert_data = None
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    message_dict = {"operation": operation, "certificate": cert_data.hex()}
elif operation == "revoke":
    name = sys.argv[3]
    message_dict = {"operation": operation, "name": name}
else:
    print("Operations not supported. Use create or revoke operations")
    sys.exit(2)

private_key_data = None
with open(private_key_path, "rb") as private_key_file:
    private_key_data = private_key_file.read()

private_key = serialization.load_pem_private_key(private_key_data, password=None)

message = dict_to_bytes(message_dict)
signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

output = message_dict.copy()
output["signature"] = signature.hex()
print(json.dumps(output))
