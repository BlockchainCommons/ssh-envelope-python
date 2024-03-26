from typing import Any, TypeVar

from ssh_envelope.cbor_utils import extract_cbor_tag_and_value, tagged_string
from ssh_envelope.run_command import run_command
from ssh_envelope.ssh_keygen_utils import sign_message
from ssh_envelope.ssh_private_key import SSHPrivateKey
from ssh_envelope.ssh_public_key import SSHPublicKey
from ssh_envelope.ssh_signature import SSHSignature
from ssh_envelope.cbor_utils import ssh_private_key_tag, ssh_public_key_tag, ssh_signature_tag

Self = TypeVar('Self', bound='Envelope')

class Envelope:
    def __init__(self, ur: str):
        if not ur.startswith("ur:envelope/"):
            raise ValueError("Not an envelope UR")
        self._ur = ur

    def __repr__(self):
        return self._ur

    def __eq__(self, other):
        if isinstance(other, Envelope):
            return self._ur == other._ur
        return False

    def __hash__(self):
        return hash(self._ur)

    @property
    def ur(self):
        return self._ur

    @property
    def digest(self):
        hex = run_command(["envelope", "digest", "--hex", self.ur]).decode()
        return bytes.fromhex(hex)

    @property
    def subject(self):
        return self.__class__(run_command(["envelope", "extract", "envelope", self.ur]).decode().strip())

    @property
    def format(self):
        return run_command(["envelope", "format", self.ur]).decode().strip()

    @classmethod
    def from_string(cls, string: str):
        return cls(run_command(["envelope", "subject", "type", "string", string]).decode().strip())

    @classmethod
    def from_tagged_string(cls, tag: int, string: str):
        hex = tagged_string(tag, string).hex()
        return cls(run_command(["envelope", "subject", "type", "cbor", hex]).decode().strip())

    @classmethod
    def from_known_value(cls, value: int | str):
        return cls(run_command(["envelope", "subject", "type", "known", str(value)]).decode().strip())

    @classmethod
    def from_assertion_pred_obj(cls, pred_type: str, pred_value: int | str, obj_type: str, obj_value: int | str):
        return cls(run_command(["envelope", "subject", "assertion", pred_type, str(pred_value), obj_type, str(obj_value)]).decode().strip())

    @classmethod
    def from_ssh_private_key(cls, private_key: SSHPrivateKey):
        return cls.from_tagged_string(ssh_private_key_tag, private_key.pem)

    def to_ssh_private_key(self) -> SSHPrivateKey:
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_private_key_tag:
            return SSHPrivateKey(value)
        else:
            raise ValueError("Invalid SSH private key")

    @classmethod
    def from_ssh_public_key(cls, public_key: SSHPublicKey):
        return cls.from_tagged_string(ssh_public_key_tag, public_key.value)

    def to_ssh_public_key(self) -> SSHPublicKey:
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_public_key_tag:
            return SSHPublicKey(value)
        else:
            raise ValueError("Invalid SSH public key")

    @classmethod
    def from_ssh_signature(cls, signature: SSHSignature):
        return cls.from_tagged_string(ssh_signature_tag, signature.pem)

    def to_ssh_signature(self) -> SSHSignature:
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_signature_tag:
            return SSHSignature(value)
        else:
            raise ValueError("Invalid SSH signature")

    @classmethod
    def from_ssh_object(cls, ssh_object: SSHPrivateKey | SSHPublicKey | SSHSignature):
        if isinstance(ssh_object, SSHPrivateKey):
            return cls.from_ssh_private_key(ssh_object)
        elif isinstance(ssh_object, SSHPublicKey):
            return cls.from_ssh_public_key(ssh_object)
        elif isinstance(ssh_object, SSHSignature):
            return cls.from_ssh_signature(ssh_object)
        else:
            raise ValueError("Invalid SSH object")

    def to_ssh_object(self) -> SSHPrivateKey | SSHPublicKey | SSHSignature:
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_private_key_tag:
            return SSHPrivateKey(value)
        elif tag == ssh_public_key_tag:
            return SSHPublicKey(value)
        elif tag == ssh_signature_tag:
            return SSHSignature(value)
        else:
            raise ValueError("Invalid SSH object")

    def add_assertion(self: Self, pred: Self, obj: Self) -> Self:
        return self.__class__(run_command(["envelope", "assertion", "add", "pred-obj", "envelope", pred.ur, "envelope", obj.ur, self.ur]).decode().strip())

    def wrapped(self):
        return self.__class__(run_command(["envelope", "subject", "type", "wrapped", self.ur]).decode().strip())

    def extract_tagged_cbor_subject(self) -> tuple[int, Any]:
        hex = run_command(["envelope", "extract", "cbor", self.ur]).decode()
        return extract_cbor_tag_and_value(bytes.fromhex(hex))

    def sign(self: Self, private_key: Self, namespace: str | None = None) -> Self:
        signature = Envelope.from_ssh_signature(sign_message(self.subject.digest, private_key.to_ssh_private_key(), namespace))
        return self.add_assertion(self.from_known_value("verifiedBy"), signature)
