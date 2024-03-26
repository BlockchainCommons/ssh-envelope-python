from typing import Any
import cbor2

ssh_private_key_tag = 40800
ssh_public_key_tag = 40801
ssh_signature_tag = 40802
ssh_certificate_tag = 40803

def tagged_string(tag: int, string: str) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(tag, string))

def extract_cbor_tag_and_value(cbor: bytes) -> tuple[int, Any]:
    c = cbor2.loads(cbor)
    return c.tag, c.value
