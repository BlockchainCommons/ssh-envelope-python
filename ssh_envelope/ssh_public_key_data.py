from typing import List
from ssh_envelope.ssh_buffer import SSHReadBuffer, SSHWriteBuffer
from ssh_envelope.ssh_hash import SSHHash
from ssh_envelope.ssh_key_type import ECDSAType, SSHKeyType

class SSHPublicKeyData:
    def __init__(self,
                 buf: SSHReadBuffer,
                 key_type: SSHKeyType
                 ):
        self.type = key_type
        if key_type == SSHKeyType.RSA:
            public_exponent = buf.read_chunk()
            modulus = buf.read_chunk()
            self.data = [public_exponent, modulus]
        elif key_type == SSHKeyType.DSA:
            p = buf.read_chunk()
            q = buf.read_chunk()
            g = buf.read_chunk()
            y = buf.read_chunk()
            self.data = [p, q, g, y]
        elif key_type == SSHKeyType.ECDSA:
            type_string = buf.read_length_prefixed_string()
            subtype = ECDSAType.from_string(type_string)
            if not subtype or subtype != key_type.subtype:
                raise ValueError("Invalid ECDSA type")
            data = buf.read_chunk()
            self.data = [data]
        elif key_type == SSHKeyType.ED25519:
            data = buf.read_chunk()
            self.data = [data]
        else:
            raise ValueError("Invalid key type")

    @property
    def chunks(self) -> List[bytes]:
        if self.type in [SSHKeyType.RSA, SSHKeyType.DSA, SSHKeyType.ED25519]:
            return self.data
        elif self.type == SSHKeyType.ECDSA:
            return [str(self.type.subtype).encode(), self.data[0]]
            # return self.data
        else:
            raise ValueError("Invalid key type")

    def __eq__(self, other):
        if isinstance(other, SSHPublicKeyData):
            return self.type == other.type and self.data == other.data
        return False

    def __str__(self) -> str:
        if self.type == SSHKeyType.RSA:
            public_exponent, modulus = self.data
            return f"(public_exponent: {public_exponent.hex()}, modulus: {modulus.hex()})"
        elif self.type == SSHKeyType.DSA:
            p, q, g, y = self.data
            return f"(p: {p.hex()}, q: {q.hex()}, g: {g.hex()}, y: {y.hex()})"
        elif self.type in [SSHKeyType.ECDSA, SSHKeyType.ED25519]:
            return self.data[0].hex()
        else:
            raise ValueError("Invalid key type")

    @property
    def hash_image(self) -> bytes:
        buf = SSHWriteBuffer()
        buf.write_length_prefixed_string(str(self.type))
        if self.type in [SSHKeyType.RSA, SSHKeyType.DSA, SSHKeyType.ED25519]:
            buf.write_chunks(self.data)
        elif self.type == SSHKeyType.ECDSA:
            buf.write_length_prefixed_string(str(self.type.subtype))
            buf.write_chunks(self.data)
        return buf.data

    def hash(self, algorithm = SSHHash.Algorithm.SHA256) -> SSHHash:
        return SSHHash.from_hash_image(self.hash_image, algorithm)

    @property
    def key_size(self) -> int:
        if self.type == SSHKeyType.RSA:
            modulus = self.data[1]
            count = len(modulus) if len(modulus) % 2 == 0 else len(modulus) - 1
            return count * 8
        elif self.type == SSHKeyType.DSA:
            p = self.data[0]
            count = len(p) if len(p) % 2 == 0 else len(p) - 1
            return count * 8
        elif self.type == SSHKeyType.ED25519:
            return 32 * 8
        elif self.type == SSHKeyType.ECDSA:
            return self.type.subtype.key_size
        else:
            raise ValueError("Invalid key type")
