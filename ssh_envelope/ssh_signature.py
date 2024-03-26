class SSHSignature:
    def __init__(self, pem: str):
        pem = pem.strip()
        if not pem.startswith("-----BEGIN SSH SIGNATURE-----"):
            raise ValueError("Not an OpenSSH signature")
        self._pem = pem

    def __repr__(self):
        return self._pem

    def __eq__(self, other):
        if isinstance(other, SSHSignature):
            return self._pem == other._pem
        return False

    def __hash__(self):
        return hash(self._pem)

    @property
    def pem(self):
        return self._pem
