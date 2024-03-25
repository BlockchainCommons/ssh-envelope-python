import ssh_envelope.envelope_utils as utils
import inspect

def test_string_envelope():
    string = "Hello, CBOR!"
    envelope = utils.string_envelope(string)
    formatted_envelope = utils.format_envelope(envelope)
    assert formatted_envelope == '"Hello, CBOR!"'

def test_wrap_envelope():
    string = "Hello, CBOR!"
    envelope = utils.string_envelope(string)
    wrapped_envelope = utils.wrap_envelope(envelope)
    formatted_envelope = utils.format_envelope(wrapped_envelope)
    assert formatted_envelope == inspect.cleandoc('''
    {
        "Hello, CBOR!"
    }
    ''')

def test_tagged_string_envelope():
    string = "Hello, CBOR!"
    tag = 42
    envelope = utils.tagged_string_envelope(string, tag)
    formatted_envelope = utils.format_envelope(envelope)
    assert formatted_envelope == inspect.cleandoc('''
    42("Hello, CBOR!")
    ''')

def test_known_value_envelope():
    assert utils.format_envelope(utils.known_value_envelope(12345)) == "'12345'"
    assert utils.format_envelope(utils.known_value_envelope(1)) == "'isA'"

def test_assertion_envelope():
    assert utils.format_envelope(utils.assertion_envelope("known", 1, "string", "dog")) == inspect.cleandoc('''
    'isA': "dog"
    ''')

def test_ssh_private_key_envelope():
    assert utils.format_envelope(utils.ssh_private_key_envelope("PRIVATE_KEY")) == inspect.cleandoc('''
    40800("PRIVATE_KEY")
    ''')

def test_ssh_public_key_envelope():
    assert utils.format_envelope(utils.ssh_public_key_envelope("PUBLIC_KEY")) == inspect.cleandoc('''
    40801("PUBLIC_KEY")
    ''')

def test_ssh_signature_envelope():
    assert utils.format_envelope(utils.ssh_signature_envelope("SIGNATURE")) == inspect.cleandoc('''
    40802("SIGNATURE")
    ''')
