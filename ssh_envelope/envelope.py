from typing import TypeVar

from ssh_envelope.cbor_utils import tagged_string
from ssh_envelope.run_command import run_command

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

    def add_assertion(self: Self, pred: Self, obj: Self) -> Self:
        return self.__class__(run_command(["envelope", "assertion", "add", "pred-obj", "envelope", pred.ur, "envelope", obj.ur, self.ur]).decode().strip())

    def wrapped(self):
        return self.__class__(run_command(["envelope", "subject", "type", "wrapped", self.ur]).decode().strip())
