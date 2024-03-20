from ssh_envelope.utils.cbor import encode_tagged_string

def test_encode_tagged_string():
    # Test case 1: Basic string with tag 42
    string = "Hello, CBOR!"
    tag = 42
    expected_output = 'd82a6c48656c6c6f2c2043424f5221'
    assert encode_tagged_string(string, tag).hex() == expected_output

    # Test case 2: Empty string with tag 0
    string = ""
    tag = 0
    expected_output = 'c060'
    assert encode_tagged_string(string, tag).hex() == expected_output

    # Test case 3: Unicode string with tag 1000
    string = "こんにちは"
    tag = 1000
    expected_output = 'd903e86fe38193e38293e381abe381a1e381af'
    assert encode_tagged_string(string, tag).hex() == expected_output

    # Add more test cases as needed

    print("All tests passed!")
