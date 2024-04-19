from typing import List
from ssh_envelope.ssh_buffer import SSHReadBuffer
from ssh_envelope.ssh_key_type import ECDSAType, SSHKeyType
from ssh_envelope.ssh_utils import parse_public_key_data
from ssh_envelope.ssh_public_key_data import SSHPublicKeyData

class SSHPrivateKeyData:
    def __init__(self, buf: SSHReadBuffer, key_type: SSHKeyType, public_key_data: SSHPublicKeyData):
        self.type = key_type
        if key_type == SSHKeyType.RSA:
            type_string = buf.read_length_prefixed_string()
            if type_string != str(key_type):
                raise ValueError("Invalid key type")
            modulus = buf.read_chunk()
            public_exponent = buf.read_chunk()
            private_exponent = buf.read_chunk()
            prime1 = buf.read_chunk()
            prime2 = buf.read_chunk()
            coefficient = buf.read_chunk()
            self.data = [modulus, public_exponent, private_exponent, prime1, prime2, coefficient]
        elif key_type == SSHKeyType.DSA:
            public_key_data_2 = parse_public_key_data(buf, key_type)
            if public_key_data != public_key_data_2:
                raise ValueError("OpenSSH private key: Public key mismatch")
            x = buf.read_chunk()
            self.data = [x]
        elif key_type == SSHKeyType.ECDSA:
            type_string = buf.read_length_prefixed_string()
            subtype = ECDSAType.from_string(type_string)
            if not subtype or subtype != key_type.value[1]:
                raise ValueError("Invalid ECDSA type")
            data = buf.read_chunk()
            self.data = [data]
        elif key_type == SSHKeyType.ED25519:
            public_key_data_2 = parse_public_key_data(buf, key_type)
            if public_key_data != public_key_data_2:
                raise ValueError("OpenSSH private key: Public key mismatch")
            data = buf.read_chunk()
            if len(data) != 64:
                raise ValueError("Invalid key length")
            private_key = data[:32]
            public_key = data[32:]
            self.data = [private_key, public_key]
        else:
            raise ValueError("Invalid key type")

    @property
    def chunks(self) -> List[bytes]:
        if self.type in [SSHKeyType.RSA, SSHKeyType.DSA]:
            return self.data
        elif self.type == SSHKeyType.ED25519:
            return [self.data[0] + self.data[1]]
        elif self.type == SSHKeyType.ECDSA:
            return [str(type).encode(), self.data[0]]
        else:
            raise ValueError("Invalid key type")

    def __str__(self) -> str:
        if self.type == SSHKeyType.RSA:
            modulus, public_exponent, private_exponent, prime1, prime2, coefficient = self.data
            return f"(modulus: {modulus.hex()}, publicExponent: {public_exponent.hex()}, privateExponent: {private_exponent.hex()}, prime1: {prime1.hex()}, prime2: {prime2.hex()}, coefficient: {coefficient.hex()})"
        elif self.type == SSHKeyType.DSA:
            return self.data[0].hex()
        elif self.type == SSHKeyType.ECDSA:
            return self.data[0].hex()
        elif self.type == SSHKeyType.ED25519:
            return (self.data[0] + self.data[1]).hex()
        else:
            raise ValueError("Invalid key type")

    def __eq__(self, other):
        if isinstance(other, SSHPrivateKeyData):
            return self.type == other.type and self.data == other.data
        return False
