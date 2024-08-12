from backend.utils import check_certificate_valid


def test_valid_signed_cert_return_true():
    valid_cert_data = None
    with open("tests/signed_cert1.pem", "rb") as valid_cert_file:
        valid_cert_data = valid_cert_file.read()
    assert check_certificate_valid(valid_cert_data) is True


def test_corrupted_signed_cert_return_false():
    valid_cert_data = None
    with open("tests/invalid_cert1.pem", "rb") as valid_cert_file:
        valid_cert_data = valid_cert_file.read()
    assert check_certificate_valid(valid_cert_data) is False

def test_invalid_signed_cert_return_false():
    valid_cert_data = None
    with open("tests/invalid_cert2.pem", "rb") as valid_cert_file:
        valid_cert_data = valid_cert_file.read()
    assert check_certificate_valid(valid_cert_data) is False
