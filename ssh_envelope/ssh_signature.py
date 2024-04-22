from ssh_envelope.pem import PEM
from ssh_envelope.ssh_buffer import SSHReadBuffer, SSHWriteBuffer
from ssh_envelope.ssh_hash import SSHHash
from ssh_envelope.ssh_key_type import SSHKeyType
from ssh_envelope.ssh_public_key_data import SSHPublicKeyData
from ssh_envelope.ssh_utils import parse_public_key_data

pem_header = "SSH SIGNATURE"
magic = "SSHSIG".encode()

class SSHSignature:
    def __init__(self,
                 public_key_data: SSHPublicKeyData,
                 namespace: str,
                 hash_algorithm: SSHHash.Algorithm,
                 data: bytes,
                 ):
        self._public_key_data = public_key_data
        self._namespace = namespace
        self._hash_algorithm = hash_algorithm
        self._data = data

    @classmethod
    def from_pem_string(cls, value: str) -> "SSHSignature":
        pem = PEM.from_pem_string(value)
        if not pem.header == pem_header:
            raise ValueError("Not an OpenSSH signature")
        buf = SSHReadBuffer(pem.data)
        if not buf.read(len(magic)) == magic:
            raise ValueError("OpenSSH signature: magic value mismatch")
        version = buf.read_int()
        if version != 1:
            raise ValueError("OpenSSH signature: Unsupported version")
        public_key_chunk = buf.read_chunk()
        pub_buf = SSHReadBuffer(public_key_chunk)
        public_key_data = parse_public_key_data(pub_buf)
        if not pub_buf.is_at_end:
            raise ValueError("OpenSSH signature: Extra data after public key")
        namespace = buf.read_length_prefixed_string()
        reserved = buf.read_chunk()
        if not len(reserved) == 0:
            raise ValueError("OpenSSH signature: Reserved field not empty")

        hash_algorithm_string = buf.read_length_prefixed_string()
        hash_algorithm = SSHHash.Algorithm.from_string(hash_algorithm_string)

        sig_chunk = buf.read_chunk()
        sig_buf = SSHReadBuffer(sig_chunk)
        sig_key_type_string = sig_buf.read_length_prefixed_string()
        sig_key_type = SSHKeyType.from_string(sig_key_type_string)
        if sig_key_type != public_key_data.type:
            raise ValueError("OpenSSH signature: Signature key type mismatch")
        data = sig_buf.read_chunk()
        if not sig_buf.is_at_end:
            raise ValueError("OpenSSH signature: Extra data after signature")

        return cls(public_key_data, namespace, hash_algorithm, data)

    def __repr__(self):
        return self.pem_string

    def __eq__(self, other):
        if isinstance(other, SSHSignature):
            return self.pem == other.pem
        return False

    def __hash__(self):
        return hash(self.pem)

    @property
    def public_key_data(self) -> SSHPublicKeyData:
        return self._public_key_data

    @property
    def namespace(self) -> str:
        return self._namespace

    @property
    def hash_algorithm(self) -> SSHHash.Algorithm:
        return self._hash_algorithm

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def pem(self) -> PEM:
        buf = SSHWriteBuffer()
        buf.write(magic)

        buf.write_int(1) # version

        pub_buf = SSHWriteBuffer()
        pub_buf.write_length_prefixed_string(str(self.public_key_data.type))
        pub_buf.write_chunks(self.public_key_data.chunks)
        buf.write_chunk(pub_buf.data)

        buf.write_length_prefixed_string(self.namespace)

        buf.write_empty_chunk() # reserved

        buf.write_length_prefixed_string(str(self.hash_algorithm).lower())

        sig_buf = SSHWriteBuffer()
        sig_buf.write_length_prefixed_string(str(self.public_key_data.type))
        sig_buf.write_chunk(self.data)
        buf.write_chunk(sig_buf.data)

        return PEM.from_header_and_data(pem_header, buf.data)

    @property
    def pem_string(self) -> str:
        return self.pem.pem_string
