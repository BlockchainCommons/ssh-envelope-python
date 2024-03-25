import cbor2

def tagged_string_hex(string: str, tag: int) -> str:
    return cbor2.dumps(cbor2.CBORTag(tag, string)).hex()

def extract_cbor_tag_and_value(cbor_hex: str) -> tuple[int, str]:
    c = cbor2.loads(bytes.fromhex(cbor_hex))
    return c.tag, c.value
