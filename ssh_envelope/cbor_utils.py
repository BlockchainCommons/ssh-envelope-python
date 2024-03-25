from typing import Any
import cbor2

def tagged_string(tag: int, string: str) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(tag, string))

def extract_cbor_tag_and_value(cbor: bytes) -> tuple[int, Any]:
    c = cbor2.loads(cbor)
    return c.tag, c.value
