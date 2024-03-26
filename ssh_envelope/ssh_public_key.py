class SSHPublicKey:
    def __init__(self, value: str):
        # value = value.strip()
        if len(value.splitlines()) != 1:
            raise ValueError("Not an OpenSSH public key")
        self._value = value
        self._parts = value.split()
        if len(self._parts) < 2:
            raise ValueError("Not an OpenSSH public key")
        self._type = self._parts[0]
        self._base64 = self._parts[1]
        self._identity = self._parts[2] if len(self._parts) > 2 else None

    def __repr__(self):
        return self._value

    def __eq__(self, other):
        if isinstance(other, SSHPublicKey):
            return self._value == other._value
        return False

    def __hash__(self):
        return hash(self._value)

    @property
    def value(self):
        return self._value

    @property
    def parts(self):
        return self._parts

    @property
    def type(self):
        return self._type

    @property
    def base64(self):
        return self._base64

    @property
    def identity(self):
        return self._identity
