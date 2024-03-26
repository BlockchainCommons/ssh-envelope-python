from ssh_envelope.cbor_utils import extract_cbor_tag_and_value
from ssh_envelope.run_command import run_command
from ssh_envelope.envelope import Envelope
from ssh_envelope.ssh_private_key import SSHPrivateKey
from ssh_envelope.ssh_public_key import SSHPublicKey
from ssh_envelope.ssh_signature import SSHSignature
from ssh_envelope.cbor_utils import ssh_private_key_tag, ssh_public_key_tag, ssh_signature_tag

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
