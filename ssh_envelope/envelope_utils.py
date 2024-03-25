from ssh_envelope.cbor_utils import extract_cbor_tag_and_value, tagged_string_hex
from ssh_envelope.run_command import run_command

ssh_private_key_tag = 40800
ssh_public_key_tag = 40801
ssh_signature_tag = 40802
ssh_certificate_tag = 40803

def format_envelope(envelope: str) -> str:
    return run_command(["envelope", "format", envelope])

def string_envelope(string: str) -> str:
    return run_command(["envelope", "subject", "type", "string", string])

def wrap_envelope(envelope: str) -> str:
    return run_command(["envelope", "subject", "type", "wrapped", envelope])

def tagged_string_envelope(string: str, tag: int) -> str:
    hex = tagged_string_hex(string, tag)
    return run_command(["envelope", "subject", "type", "cbor", hex])

def known_value_envelope(value: int | str) -> str:
    return run_command(["envelope", "subject", "type", "known", str(value)])

def assertion_envelope(pred_type: str, pred_value: int | str, obj_type: str, obj_value: int | str) -> str:
    return run_command(["envelope", "subject", "assertion", pred_type, str(pred_value), obj_type, str(obj_value)])

def verified_by_assertion_envelope(signature_cbor_hex: str) -> str:
    return assertion_envelope("known", "verifiedBy", "cbor", signature_cbor_hex)

def ssh_private_key_envelope(private_key_string: str) -> str:
    return tagged_string_envelope(private_key_string, ssh_private_key_tag)

def ssh_public_key_envelope(public_key_string: str) -> str:
    return tagged_string_envelope(public_key_string, ssh_public_key_tag)

def ssh_signature_envelope(signature_string: str) -> str:
    return tagged_string_envelope(signature_string, ssh_signature_tag)

def extract_tagged_cbor_subject(envelope: str):
    return run_command(["envelope", "extract", "cbor", envelope])

def export_private_key(envelope: str) -> str:
    cbor = extract_tagged_cbor_subject(envelope)
    tag, value = extract_cbor_tag_and_value(cbor)
    if tag == ssh_private_key_tag:
        return value
    else:
        raise ValueError("Invalid SSH private key")

def export_public_key(envelope: str) -> str:
    cbor = extract_tagged_cbor_subject(envelope)
    tag, value = extract_cbor_tag_and_value(cbor)
    if tag == ssh_public_key_tag:
        return value
    else:
        raise ValueError("Invalid SSH public key")

def export_signature(envelope: str) -> str:
    cbor = extract_tagged_cbor_subject(envelope)
    tag, value = extract_cbor_tag_and_value(cbor)
    if tag == ssh_signature_tag:
        return value
    else:
        raise ValueError("Invalid SSH signature")

def export_ssh_object(envelope: str) -> str:
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
