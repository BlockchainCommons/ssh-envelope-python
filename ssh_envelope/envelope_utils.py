from ssh_envelope.cbor_utils import extract_cbor_tag_and_value, tagged_string, tagged_string
from ssh_envelope.run_command import run_command
from ssh_envelope.envelope import Envelope
from ssh_envelope.ssh_private_key import SSHPrivateKey
from ssh_envelope.ssh_public_key import SSHPublicKey
from ssh_envelope.ssh_signature import SSHSignature

ssh_private_key_tag = 40800
ssh_public_key_tag = 40801
ssh_signature_tag = 40802
ssh_certificate_tag = 40803

# def known_value_envelope(value: int | str) -> Envelope:
#     return Envelope(run_command(["envelope", "subject", "type", "known", str(value)]).decode().strip())

def assertion_envelope(pred_type: str, pred_value: int | str, obj_type: str, obj_value: int | str) -> Envelope:
    return Envelope(run_command(["envelope", "subject", "assertion", pred_type, str(pred_value), obj_type, str(obj_value)]).decode().strip())

def ssh_private_key_envelope(private_key: SSHPrivateKey) -> Envelope:
    return Envelope.from_tagged_string(ssh_private_key_tag, private_key.pem)

def ssh_public_key_envelope(public_key: SSHPublicKey) -> Envelope:
    return Envelope.from_tagged_string(ssh_public_key_tag, public_key.value)

def ssh_signature_envelope(signature: SSHSignature) -> Envelope:
    return Envelope.from_tagged_string(ssh_signature_tag, signature.pem)

def extract_tagged_cbor_subject(envelope: Envelope) -> bytes:
    hex = run_command(["envelope", "extract", "cbor", envelope.ur]).decode()
    return bytes.fromhex(hex)

def export_private_key(envelope: Envelope) -> SSHPrivateKey:
    cbor = extract_tagged_cbor_subject(envelope)
    tag, value = extract_cbor_tag_and_value(cbor)
    if tag == ssh_private_key_tag:
        return SSHPrivateKey(value)
    else:
        raise ValueError("Invalid SSH private key")

def export_public_key(envelope: Envelope) -> SSHPublicKey:
    cbor = extract_tagged_cbor_subject(envelope)
    tag, value = extract_cbor_tag_and_value(cbor)
    if tag == ssh_public_key_tag:
        return SSHPublicKey(value)
    else:
        raise ValueError("Invalid SSH public key")

def export_signature(envelope: Envelope) -> SSHSignature:
    cbor = extract_tagged_cbor_subject(envelope)
    tag, value = extract_cbor_tag_and_value(cbor)
    if tag == ssh_signature_tag:
        return SSHSignature(value)
    else:
        raise ValueError("Invalid SSH signature")

def export_ssh_object(envelope: Envelope) -> SSHPrivateKey | SSHPublicKey | SSHSignature:
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
