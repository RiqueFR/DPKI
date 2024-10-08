import json
import logging
import traceback
from os import environ

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from utils import (
    add_user_certificate,
    check_signature_belongs_to_certificate_valid,
    dict_to_bytes,
    update_certificate_status,
)
from db_handler import DB

logging.basicConfig(level="INFO")
logger = logging.getLogger(__name__)

rollup_server = environ["ROLLUP_HTTP_SERVER_URL"]
logger.info(f"HTTP rollup_server url is {rollup_server}")

db = DB()


def hex2str(hex):
    """
    Decodes a hex string into a regular string
    """
    return bytes.fromhex(hex[2:]).decode("utf-8")


def str2hex(str):
    """
    Encodes a string as a hex string
    """
    return "0x" + str.encode("utf-8").hex()


def handle_advance(data):
    logger.info(f"Received advance request data {data}")

    status = "accept"
    output = ""
    try:
        input_json_str = hex2str(data["payload"])
        logger.info(f"Received input: {input_json_str}")

        input_json = json.loads(input_json_str)

        # check input json have operation key
        if "operation" not in input_json:
            raise Exception("Bad formated json input, no operation key")

        operation = input_json["operation"]

        if operation == "create":
            # check input json have certificate key
            if "certificate" not in input_json:
                raise Exception(
                    "Bad formated json input, create operation require a certificate"
                )
            # check input json have signature key
            if "signature" not in input_json:
                raise Exception(
                    "Bad formated json input, create operation require a signature"
                )
            certificate_hex = input_json["certificate"]
            signature_hex = input_json["signature"]

            certificate = bytes.fromhex(certificate_hex)
            signature = bytes.fromhex(signature_hex)

            message = dict_to_bytes(
                {"operation": "create", "certificate": certificate_hex}
            )

            cert = x509.load_pem_x509_certificate(certificate)
            public_key = cert.public_key()
            common_name = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
            public_key_hex = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).hex()
            due_date = cert.not_valid_after_utc
            due_date_str = due_date.strftime("%Y-%m-%d %H:%M:%S")

            # check if user is already in database
            if db.get_certificate_by_user(common_name):
                raise Exception("Certificate with this Common Name already registered")

            # check certificate is valid
            if not check_signature_belongs_to_certificate_valid(
                cert.tbs_certificate_bytes, public_key, cert.signature
            ):
                raise Exception("Invalid certificate")

            # check signature is valid
            if not check_signature_belongs_to_certificate_valid(
                message, public_key, signature
            ):
                raise Exception("Invalid signature")

            logger.info("Valid input, creating data")

            # add to database
            if not add_user_certificate(db, common_name, cert):
                raise Exception("Failed to add certificate to database")

            # set output to the blockchain
            output = {
                "userId": common_name,
                "certificate": certificate_hex,
                "publicKey": public_key_hex,
                "active": True,
                "dueDate": due_date_str,
            }
        elif operation == "revoke":
            # check input json have signature key
            if "signature" not in input_json:
                raise Exception(
                    "Bad formated json input, revoke operation require a signature"
                )
            # check input json have name key
            if "name" not in input_json:
                raise Exception(
                    "Bad formated json input, revoke operation require a name"
                )

            signature_hex = input_json["signature"]
            signature = bytes.fromhex(signature_hex)

            user_id = input_json["name"]
            user = db.get_certificate_by_user(user_id)

            # check if user is in database
            if user is None:
                raise Exception("User not found, unable to revoke key")

            # certificate already revoked
            if not user[2]:
                raise Exception("Certificate already revoked")

            user_cert_hex = user[1]

            certificate = bytes.fromhex(user_cert_hex)
            cert = x509.load_pem_x509_certificate(certificate)

            public_key = cert.public_key()
            common_name = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
            public_key_hex = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).hex()

            message = dict_to_bytes({"operation": "revoke", "name": user_id})

            # check signature is valid
            if not check_signature_belongs_to_certificate_valid(
                message, public_key, signature
            ):
                raise Exception("Invalid signature")

            # update certificate state
            if not update_certificate_status(db, user_id, False):
                raise Exception("Revoke Failed")

            logger.info("Revoked Certificate")

            # set output to the blockchain
            output = {
                "userId": common_name,
                "certificate": user_cert_hex,
                "publicKey": public_key_hex,
                "active": False,
                "dueDate": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
            }
        else:
            raise Exception(
                "Operation does not exist, use only create or revoke operations"
            )

        # Emits notice with result of calculation
        logger.info(f"Adding notice with payload: '{output}'")
        response = requests.post(
            rollup_server + "/notice",
            json={"payload": "0x" + dict_to_bytes(output).hex()},
        )
        logger.info(
            f"Received notice status {response.status_code} body {response.content}"
        )

    except Exception as e:
        status = "reject"
        msg = f"Error processing data {data}\n{traceback.format_exc()}"
        logger.error(msg)
        response = requests.post(
            rollup_server + "/report", json={"payload": str2hex(msg)}
        )
        logger.info(
            f"Received report status {response.status_code} body {response.content}"
        )

    return status


def handle_inspect(data):
    """
    Consult user register.
    """
    logger.info(f"Received inspect request data {data}")
    logger.info("Adding report")

    user_id = hex2str(data["payload"])
    cert = db.get_certificate_by_user(user_id)

    output = {
        "name": cert[0],
        "certificate_hex": cert[1],
        "status": "active" if cert[2] else "revoked",
        "public_key_hex": cert[3],
        "due_date": cert[4],
    }
    response = requests.post(
        rollup_server + "/report", json={"payload": "0x" + dict_to_bytes(output).hex()}
    )

    logger.info(f"response received from report {response}")
    logger.info(f"response received from report {response.content}")

    logger.info(f"Received report status {response.status_code}")
    return "accept"


handlers = {
    "advance_state": handle_advance,
    "inspect_state": handle_inspect,
}

finish = {"status": "accept"}

while True:
    logger.info("Sending finish")
    response = requests.post(rollup_server + "/finish", json=finish)
    logger.info(f"Received finish status {response.status_code}")
    if response.status_code == 202:
        logger.info("No pending rollup request, trying again")
    else:
        rollup_request = response.json()
        data = rollup_request["data"]

        handler = handlers[rollup_request["request_type"]]
        finish["status"] = handler(rollup_request["data"])
