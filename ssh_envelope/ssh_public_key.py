import base64
from typing import List
from ssh_envelope.ssh_buffer import SSHReadBuffer, SSHWriteBuffer
from ssh_envelope.ssh_hash import SSHHash
from ssh_envelope.ssh_key_type import SSHKeyType
from ssh_envelope.ssh_public_key_data import SSHPublicKeyData
from ssh_envelope.ssh_utils import parse_public_key_data
from ssh_envelope.string_utils import compact_joined, compact_joined_key_values

class SSHPublicKey:
    def __init__(self,
                 key_data: SSHPublicKeyData,
                 comment: str
                 ):
        self._key_data = key_data
        self._comment = comment

    @classmethod
    def from_string(cls, value: str) -> "SSHPublicKey":
        if len(value.splitlines()) != 1:
            raise ValueError("Not an OpenSSH public key")
        parts = value.strip().split(" ")
        if len(parts) < 2:
            raise ValueError("Not an OpenSSH public key")
        type = SSHKeyType.from_string(parts[0])
        base64_data = parts[1]
        decoded_data = base64.b64decode(base64_data)
        buf = SSHReadBuffer(decoded_data)
        key_data = parse_public_key_data(buf)
        if type != key_data.type:
            raise ValueError("Public key type mismatch")
        comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
        return cls(key_data, comment)

    def __repr__(self) -> str:
        return f"SSHPublicKey({compact_joined_key_values([
            ('type', self.type),
            ('key_data', self.key_data),
            ('comment', self.comment)
        ], separator=', ')})"

    def __eq__(self, other):
        if isinstance(other, SSHPublicKey):
            return self.key_data == other.key_data and self.comment == other.comment
        return False

    def __hash__(self):
        return hash(repr(self))

    def hash(self, algorithm: SSHHash.Algorithm = SSHHash.Algorithm.SHA256) -> SSHHash:
        return self.key_data.hash(algorithm)

    @property
    def key_data(self):
        return self._key_data

    @property
    def type(self) -> SSHKeyType:
        return self.key_data.type

    @property
    def chunks(self) -> List[bytes]:
        return [str(self.type).encode()] + self.key_data.chunks

    @property
    def base64_string(self):
        data = SSHWriteBuffer.chunks_to_data(self.chunks)
        return base64.b64encode(data).decode()

    @property
    def string(self):
        return compact_joined([
            str(self.type),
            self.base64_string,
            self.comment
        ], separator=' ')

    @property
    def key_size(self) -> int:
        return self.key_data.key_size

    @property
    def fingerprint(self) -> str:
        return str(self.hash())

    @property
    def comment(self) -> str:
        return self._comment or ""

    @comment.setter
    def comment(self, value: str):
        self._comment = value

    @property
    def type_name(self) -> str:
        return str(self.type.name)

    @property
    def hash_string(self):
        return " ".join([
            str(self.key_size),
            str(self.fingerprint),
            self.comment,
            f"({self.type_name})",
        ])
