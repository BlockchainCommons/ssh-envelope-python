from ssh_envelope.pem import PEM


class SSHSignature:
    def __init__(self, pem: PEM):
        if not pem.header == "SSH SIGNATURE":
            raise ValueError("Not an OpenSSH signature")
        self._pem = pem

    @classmethod
    def from_pem_string(cls, value: str) -> "SSHSignature":
        pem = PEM.from_pem_string(value)
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
