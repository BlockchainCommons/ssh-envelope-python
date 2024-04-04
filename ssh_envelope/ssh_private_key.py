from ssh_envelope.pem import PEM


class SSHPrivateKey:
    def __init__(self, pem_string: str):
        self._pem = PEM.from_pem_string(pem_string)
        if not self._pem.header == "OPENSSH PRIVATE KEY":
            raise ValueError("Not an OpenSSH private key")

    def __repr__(self):
        return self._pem.pem_string

    def __eq__(self, other):
        if isinstance(other, SSHPrivateKey):
            return self._pem == other._pem
        return False

    def __hash__(self):
        return hash(self._pem)

    @property
    def pem2(self) -> PEM:
        return self._pem

    @property
    def pem_string(self) -> str:
        return self._pem.pem_string
