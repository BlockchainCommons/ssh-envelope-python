
from ssh_envelope.ssh_buffer import SSHReadBuffer
from ssh_envelope.ssh_key_type import SSHKeyType
from ssh_envelope.ssh_public_key_data import SSHPublicKeyData


def parse_public_key_data(buf: SSHReadBuffer, check_type: SSHKeyType | None = None) -> SSHPublicKeyData:
    type_string = buf.read_length_prefixed_string()
    if check_type:
        if type_string != str(check_type):
            raise ValueError("Invalid key type")
    key_type = SSHKeyType.from_string(type_string)
    return SSHPublicKeyData(buf, key_type)

def check_comment(comment: str):
    if any([c.isspace() for c in comment]):
            raise ValueError("Comment may not contain whitespace.")
