class SSHPrivateKey:
    def __init__(self, pem: str):
        # pem = pem.strip()
        if not pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
            raise ValueError("Not an OpenSSH private key")
        self._pem = pem

    def __repr__(self):
        return self._pem

    def __eq__(self, other):
        if isinstance(other, SSHPrivateKey):
            return self._pem == other._pem
        return False

    def __hash__(self):
        return hash(self._pem)

    @property
    def pem(self):
        return self._pem
