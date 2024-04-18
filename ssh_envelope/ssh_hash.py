from enum import Enum
from base64 import b64encode, b64decode
from typing import Union
from hashlib import sha256

class SSHHash:
    class Algorithm(Enum):
        SHA256 = "SHA256"
        MD5 = "MD5"

        def __str__(self):
            return self.value

    def __init__(self, data: Union[bytes, str], algorithm: Algorithm = Algorithm.SHA256):
        if isinstance(data, str):
            if algorithm == self.Algorithm.SHA256:
                if len(data) != 43:
                    raise ValueError("Invalid SHA256 hash string")
                try:
                    data = b64decode(data + "=")
                except:
                    raise ValueError("Invalid SHA256 hash string")
            elif algorithm == self.Algorithm.MD5:
                data = data.replace(":", "")
                try:
                    data = bytes.fromhex(data)
                except:
                    raise ValueError("Invalid MD5 hash string")
                if len(data) != 16:
                    raise ValueError("Invalid MD5 hash length")

        if algorithm == self.Algorithm.SHA256 and len(data) != 32:
            raise ValueError("Invalid SHA256 hash length")
        elif algorithm == self.Algorithm.MD5 and len(data) != 16:
            raise ValueError("Invalid MD5 hash length")

        self.algorithm = algorithm
        self.data = data

    @classmethod
    def from_hash_image(cls, hash_image: bytes, algorithm: Algorithm = Algorithm.SHA256):
        if algorithm == cls.Algorithm.SHA256:
            data = sha256(hash_image).digest()
        elif algorithm == cls.Algorithm.MD5:
            raise NotImplementedError("MD5 not implemented")
        return cls(data, algorithm)

    @classmethod
    def from_string(cls, string: str):
        try:
            algorithm, hash_string = string.split(":", 1)
            algorithm = cls.Algorithm(algorithm)
        except (ValueError, KeyError):
            raise ValueError("Invalid SSH hash string")
        return cls(hash_string, algorithm)

    def __str__(self):
        if self.algorithm == self.Algorithm.SHA256:
            hash_string = b64encode(self.data).decode("utf-8")[:-1]
        elif self.algorithm == self.Algorithm.MD5:
            hash_string = ":".join([f"{b:02x}" for b in self.data])
        else:
            raise ValueError("Invalid hash algorithm")
        return f"{self.algorithm}:{hash_string}"
