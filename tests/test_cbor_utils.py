import ssh_envelope.cbor_utils as utils

def test_cbor_tagged_string_1():
    string = "Hello, CBOR!"
    tag = 42
    expected_output = bytes.fromhex('d82a6c48656c6c6f2c2043424f5221')
    assert utils.tagged_string(tag, string) == expected_output
    assert (tag, string) == utils.extract_cbor_tag_and_value(expected_output)

def test_cbor_tagged_string_2():
    string = ""
    tag = 1234
    expected_output = bytes.fromhex('d904d260')
    assert utils.tagged_string(tag, string) == expected_output
    assert (tag, string) == utils.extract_cbor_tag_and_value(expected_output)

def test_cbor_tagged_string_3():
    string = "こんにちは"
    tag = 1000
    expected_output = bytes.fromhex('d903e86fe38193e38293e381abe381a1e381af')
    assert utils.tagged_string(tag, string) == expected_output
    assert (tag, string) == utils.extract_cbor_tag_and_value(expected_output)
