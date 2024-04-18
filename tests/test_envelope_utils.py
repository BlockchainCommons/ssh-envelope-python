from ssh_envelope.envelope import Envelope
import inspect

def test_string_envelope():
    string = "Hello!"
    envelope = Envelope.from_string(string)
    formatted_envelope = envelope.format
    assert formatted_envelope == '"Hello!"'

def test_wrap_envelope():
    string = "Hello!"
    envelope = Envelope.from_string(string)
    wrapped_envelope = envelope.wrapped()
    formatted_envelope = wrapped_envelope.format
    assert formatted_envelope == inspect.cleandoc('''
    {
        "Hello!"
    }
    ''')

def test_tagged_string_envelope():
    string = "Hello!"
    tag = 42
    envelope = Envelope.from_tagged_string(tag, string)
    formatted_envelope = envelope.format
    assert formatted_envelope == inspect.cleandoc('''
    42("Hello!")
    ''')

def test_known_value_envelope():
    assert Envelope.from_known_value(12345).format == "'12345'"
    assert Envelope.from_known_value(1).format == "'isA'"

def test_assertion_envelope_1():
    assert Envelope.from_assertion_pred_obj("known", 1, "string", "dog").format == inspect.cleandoc('''
    'isA': "dog"
    ''')

def test_assertion_envelope_2():
    assert Envelope.from_assertion_pred_obj("known", "verifiedBy", "string", "Signature").format == inspect.cleandoc('''
    'verifiedBy': "Signature"
    ''')

test_string_envelope()
test_wrap_envelope()
test_tagged_string_envelope()
test_known_value_envelope()
test_assertion_envelope_1()
test_assertion_envelope_2()
