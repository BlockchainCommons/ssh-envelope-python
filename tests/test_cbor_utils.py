import ssh_envelope.cbor_utils as utils

def test_encode_tagged_string():
    # Test case 1: Basic string with tag 42
    string = "Hello, CBOR!"
    tag = 42
    expected_output = 'd82a6c48656c6c6f2c2043424f5221'
    assert utils.tagged_string_hex(string, tag) == expected_output
    assert (tag, string) == utils.extract_cbor_tag_and_value(expected_output)

    # Test case 2: Empty string with tag 0
    string = ""
    tag = 1234
    expected_output = 'd904d260'
    assert utils.tagged_string_hex(string, tag) == expected_output
    assert (tag, string) == utils.extract_cbor_tag_and_value(expected_output)

    # Test case 3: Unicode string with tag 1000
    string = "こんにちは"
    tag = 1000
    expected_output = 'd903e86fe38193e38293e381abe381a1e381af'
    assert utils.tagged_string_hex(string, tag) == expected_output
    assert (tag, string) == utils.extract_cbor_tag_and_value(expected_output)
