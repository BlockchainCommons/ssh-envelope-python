from ssh_envelope.ssh_buffer import SSHReadBuffer
from ssh_envelope.pem import PEM
from ssh_envelope.ssh_key_type import SSHKeyType
from ssh_envelope.ssh_private_key_data import SSHPrivateKeyData
from ssh_envelope.ssh_public_key_data import SSHPublicKeyData
from ssh_envelope.ssh_utils import parse_public_key_data
from ssh_envelope.string_utils import compact_joined_key_values

magic = "openssh-key-v1"
none = "none"

class SSHPrivateKey:
    def __init__(self, pem, public_key_data, check_num, private_key_data, comment):
        self._pem = pem
        self._public_key_data = public_key_data
        self._check_num = check_num
        self._private_key_data = private_key_data
        self._comment = comment
        self._type = self._public_key_data.type

    @classmethod
    def from_pem_string(cls, pem_string: str):
        pem = PEM.from_pem_string(pem_string)
        if not pem.header == "OPENSSH PRIVATE KEY":
            raise ValueError("Not an OpenSSH private key")
        buffer = SSHReadBuffer(pem.data)
        if not buffer.read_null_terminated_string() == magic:
            raise ValueError("OpenSSH private key: magic value mismatch")
        cipher_name = buffer.read_length_prefixed_string()
        if not cipher_name == none:
            raise ValueError("OpenSSH private key: Unsupported cipher")
        kdf_name = buffer.read_length_prefixed_string()
        if not kdf_name == none:
            raise ValueError("OpenSSH private key: Unsupported KDF")
        kdf = buffer.read_chunk()
        if not kdf == b"":
            raise ValueError("OpenSSH private key: Unsupported KDF")
        num_keys = buffer.read_int()
        if num_keys != 1:
            raise ValueError("OpenSSH private key: Expected one key")

        public_key_chunk = buffer.read_chunk()
        pub_buf = SSHReadBuffer(public_key_chunk)
        public_key_data = parse_public_key_data(pub_buf)
        if not pub_buf.is_at_end:
            raise ValueError("OpenSSH private key: Extra data after public key")

        private_key_chunk = buffer.read_chunk()
        if not buffer.is_at_end:
            raise ValueError("OpenSSH private key: Extra data after private key")
        priv_buf = SSHReadBuffer(private_key_chunk)
        check_num = priv_buf.read(4)
        check_num_2 = priv_buf.read(4)
        if check_num != check_num_2:
            raise ValueError("OpenSSH private key: Check numbers do not match")

        private_key_data = SSHPrivateKeyData(priv_buf, public_key_data.type, public_key_data)

        if priv_buf.remaining >= 4:
            comment = priv_buf.read_length_prefixed_string()
        else:
            comment = None

        priv_buf.expect_padding()
        if not priv_buf.is_at_end:
            raise ValueError("OpenSSH private key: Extra data after padding")

        return cls(pem, public_key_data, check_num, private_key_data, comment)

    def __str__(self):
        return self.pem_string

    def __repr__(self) -> str:
        return f"SSHPrivateKey({compact_joined_key_values([
            ('type', self.type),
            ('public_key_data', self.public_key_data),
            ('check_num', self.check_num.hex()),
            ('private_key_data', self.private_key_data),
            ('comment', self.comment)
        ], separator=', ')})"

    def __eq__(self, other):
        if isinstance(other, SSHPrivateKey):
            return self.pem == other._pem
        return False

    def __hash__(self):
        return hash(self.pem)

    @property
    def pem(self) -> PEM:
        return self._pem

    @property
    def pem_string(self) -> str:
        return self.pem.pem_string

    @property
    def type(self) -> SSHKeyType:
        return self._type

    @property
    def public_key_data(self) -> SSHPublicKeyData:
        return self._public_key_data

    @property
    def check_num(self) -> bytes:
        return self._check_num

    @property
    def private_key_data(self) -> SSHPrivateKeyData:
        return self._private_key_data

    @property
    def comment(self) -> str | None:
        return self._comment
