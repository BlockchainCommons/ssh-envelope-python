import ssh_envelope.envelope_utils as utils
import inspect

from ssh_envelope.ssh_private_key import SSHPrivateKey

def test_string_envelope():
    string = "Hello!"
    envelope = utils.string_envelope(string)
    formatted_envelope = utils.format_envelope(envelope)
    assert formatted_envelope == '"Hello!"'

def test_wrap_envelope():
    string = "Hello!"
    envelope = utils.string_envelope(string)
    wrapped_envelope = utils.wrap_envelope(envelope)
    formatted_envelope = utils.format_envelope(wrapped_envelope)
    assert formatted_envelope == inspect.cleandoc('''
    {
        "Hello!"
    }
    ''')

def test_tagged_string_envelope():
    string = "Hello!"
    tag = 42
    envelope = utils.tagged_string_envelope(tag, string)
    formatted_envelope = utils.format_envelope(envelope)
    assert formatted_envelope == inspect.cleandoc('''
    42("Hello!")
    ''')

def test_known_value_envelope():
    assert utils.format_envelope(utils.known_value_envelope(12345)) == "'12345'"
    assert utils.format_envelope(utils.known_value_envelope(1)) == "'isA'"

def test_assertion_envelope():
    assert utils.format_envelope(utils.assertion_envelope("known", 1, "string", "dog")) == inspect.cleandoc('''
    'isA': "dog"
    ''')
