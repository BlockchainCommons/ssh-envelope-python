import ssh_envelope.envelope_utils as eu
import inspect

def test_encode_tagged_string():
    # Test case 1: Basic string with tag 42
    string = "Hello, CBOR!"
    tag = 42
    expected_output = 'd82a6c48656c6c6f2c2043424f5221'
    assert eu.tagged_string_hex(string, tag) == expected_output

    # Test case 2: Empty string with tag 0
    string = ""
    tag = 0
    expected_output = 'c060'
    assert eu.tagged_string_hex(string, tag) == expected_output

    # Test case 3: Unicode string with tag 1000
    string = "こんにちは"
    tag = 1000
    expected_output = 'd903e86fe38193e38293e381abe381a1e381af'
    assert eu.tagged_string_hex(string, tag) == expected_output

def test_string_envelope():
    string = "Hello, CBOR!"
    envelope = eu.string_envelope(string)
    formatted_envelope = eu.format(envelope)
    assert formatted_envelope == '"Hello, CBOR!"'

def test_wrap_envelope():
    string = "Hello, CBOR!"
    envelope = eu.string_envelope(string)
    wrapped_envelope = eu.wrap_envelope(envelope)
    formatted_envelope = eu.format(wrapped_envelope)
    assert formatted_envelope == inspect.cleandoc('''
    {
        "Hello, CBOR!"
    }
    ''')

def test_tagged_string_envelope():
    string = "Hello, CBOR!"
    tag = 42
    envelope = eu.tagged_string_envelope(string, tag)
    formatted_envelope = eu.format(envelope)
    assert formatted_envelope == inspect.cleandoc('''
    42("Hello, CBOR!")
    ''')

def test_known_value_envelope():
    assert eu.format(eu.known_value_envelope(12345)) == "'12345'"
    assert eu.format(eu.known_value_envelope(1)) == "'isA'"

def test_assertion_envelope():
    assert eu.format(eu.assertion_envelope("known", 1, "string", "dog")) == inspect.cleandoc('''
    'isA': "dog"
    ''')

def test_ssh_private_key_envelope():
    assert eu.format(eu.ssh_private_key_envelope("PRIVATE_KEY")) == inspect.cleandoc('''
    40800("PRIVATE_KEY")
    ''')

def test_ssh_public_key_envelope():
    assert eu.format(eu.ssh_public_key_envelope("PUBLIC_KEY")) == inspect.cleandoc('''
    40801("PUBLIC_KEY")
    ''')

def test_ssh_signature_envelope():
    assert eu.format(eu.ssh_signature_envelope("SIGNATURE")) == inspect.cleandoc('''
    40802("SIGNATURE")
    ''')
