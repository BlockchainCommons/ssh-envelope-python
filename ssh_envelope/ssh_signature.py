from ssh_envelope.pem import PEM
from ssh_envelope.ssh_buffer import SSHReadBuffer
from ssh_envelope.ssh_hash import SSHHash
from ssh_envelope.ssh_key_type import SSHKeyType
from ssh_envelope.ssh_utils import parse_public_key_data

pem_header = "SSH SIGNATURE"
magic = "SSHSIG".encode()

class SSHSignature:
    def __init__(self,
                 pem: PEM
                 ):
        if not pem.header == pem_header:
            raise ValueError("Not an OpenSSH signature")
        self._pem = pem

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

        return cls(pem)

    def __repr__(self):
        return self.pem_string

    def __eq__(self, other):
        if isinstance(other, SSHSignature):
            return self.pem == other.pem
        return False

    def __hash__(self):
        return hash(self._pem)

    @property
    def pem(self) -> PEM:
        return self._pem

    @property
    def pem_string(self) -> str:
        return self.pem.pem_string
