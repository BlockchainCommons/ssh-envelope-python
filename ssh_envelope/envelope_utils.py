import cbor2

from .run_command import run_command

ssh_private_key_tag = 40800
ssh_public_key_tag = 40801
ssh_signature_tag = 40802
ssh_certificate_tag = 40803

def tagged_string_hex(string, tag):
    return cbor2.dumps(cbor2.CBORTag(tag, string)).hex()

def string_envelope(string):
    return run_command(["envelope", "subject", "type", "string", string])

def wrap_envelope(envelope):
    return run_command(["envelope", "subject", "type", "wrapped", envelope])

def tagged_string_envelope(string, tag):
    hex = tagged_string_hex(string, tag)
    return run_command(["envelope", "subject", "type", "cbor", hex])

def known_value_envelope(value):
    return run_command(["envelope", "subject", "type", "known", value])

def assertion_envelope(pred_type, pred_value, obj_type, obj_value):
    return run_command(["envelope", "subject", "assertion", pred_type, pred_value, obj_type, obj_value])

def verified_by_assertion_envelope(signature):
    return assertion_envelope("known", "verifiedBy", "cbor", signature)

def format_envelope(envelope):
    return run_command(["envelope", "format", envelope])

def extract_tagged_cbor_subject(envelope):
    return run_command(["envelope", "extract", "cbor", envelope])

def ssh_private_key_envelope(private_key_string):
    return tagged_string_envelope(private_key_string, ssh_private_key_tag)

def ssh_public_key_envelope(public_key_string):
    return tagged_string_envelope(public_key_string, ssh_public_key_tag)

def ssh_signature_envelope(signature_string):
    return tagged_string_envelope(signature_string, ssh_signature_tag)

def extract_cbor_tag_and_value(cbor):
    c = cbor2.loads(bytes.fromhex(cbor))
    return c.tag, c.value

def export_ssh_object(envelope):
    cbor = extract_tagged_cbor_subject(envelope)
    tag, value = extract_cbor_tag_and_value(cbor)
    if tag == ssh_private_key_tag:
        return value
    elif tag == ssh_public_key_tag:
        return value
    elif tag == ssh_signature_tag:
        return value
    else:
        raise ValueError("Invalid SSH object")
