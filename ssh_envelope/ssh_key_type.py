from enum import Enum

class ECDSAType(Enum):
    NISTP256 = "nistp256"
    NISTP384 = "nistp384"
    NISTP521 = "nistp521"

    def __str__(self):
        return self.value

    @property
    def key_size(self):
        return {
            ECDSAType.NISTP256: 256,
            ECDSAType.NISTP384: 384,
            ECDSAType.NISTP521: 521,
        }[self]

    @classmethod
    def from_string(cls, s):
        return cls(s)


class SSHKeyType(Enum):
    RSA = "ssh-rsa"
    DSA = "ssh-dss"
    ED25519 = "ssh-ed25519"
    ECDSA = "ecdsa"

    def __init__(self, value):
        self._value_ = value
        self._subtype = None

    def __str__(self):
        if self == SSHKeyType.ECDSA:
            return f"ecdsa-sha2-{self._subtype}"
        return self.value

    def __eq__(self, other):
        if isinstance(other, SSHKeyType):
            return self._value_ == other._value_ and self._subtype == other._subtype
        return False

    @property
    def hash_name(self):
        return self.name

    @property
    def subtype(self) -> ECDSAType:
        assert self == self.ECDSA and self._subtype is not None
        return self._subtype

    @classmethod
    def from_string(cls, s):
        if s.startswith("ecdsa-sha2-"):
            subtype = ECDSAType.from_string(s.replace("ecdsa-sha2-", ""))
            key_type = cls.ECDSA
            key_type._subtype = subtype
            return key_type

        return cls(s)
