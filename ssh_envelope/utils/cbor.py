import cbor2

def encode_tagged_string(string, tag):
    """
    Encodes a string with a CBOR tag.

    Args:
        string (str): The string to be encoded.
        tag (int): The unsigned integer representing the CBOR tag.

    Returns:
        bytes: The CBOR-encoded tagged string.
    """
    # Encode the string using CBOR
    encoded_tagged_string = cbor2.dumps(cbor2.CBORTag(tag, string))

    return encoded_tagged_string
