from typing import Any, TypeVar

from ssh_envelope.cbor_utils import extract_cbor_tag_and_value, tagged_string
from ssh_envelope.run_command import run_command
from ssh_envelope.ssh_keygen_utils import sign_message, verify_message
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
    def format(self):
        """
        Returns the envelope notation format of the envelope.
        """
        return run_command(["envelope", "format", self.ur]).decode().strip()

    @property
    def digest(self):
        """
        Returns the top-level digest of the envelope.
        """
        hex = run_command(["envelope", "digest", "--hex", self.ur]).decode()
        return bytes.fromhex(hex)

    @property
    def subject(self):
        """
        Returns the subject of the envelope as an envelope.
        """
        return self.__class__(run_command(["envelope", "extract", "envelope", self.ur]).decode().strip())

    @property
    def predicate(self):
        """
        Returns the predicate of the envelope.

        :raises ValueError: If this envelope is not an assertion.
        """
        return self.__class__(run_command(["envelope", "extract", "predicate", self.ur]).decode().strip())

    @property
    def object(self):
        """
        Returns the object of the envelope.

        :raises ValueError: If this envelope is not an assertion.
        """
        return self.__class__(run_command(["envelope", "extract", "object", self.ur]).decode().strip())

    @classmethod
    def from_string(cls, string: str):
        """
        Creates an envelope with a string subject.
        """
        return cls(run_command(["envelope", "subject", "type", "string", string]).decode().strip())

    @classmethod
    def from_int(cls, value: int):
        """
        Creates an envelope with an integer subject.
        """
        return cls(run_command(["envelope", "subject", "type", "number", str(value)]).decode().strip())

    @classmethod
    def from_tagged_string(cls, tag: int, string: str):
        """
        Creates an envelope with a CBOR-tagged string subject.
        """
        hex = tagged_string(tag, string).hex()
        return cls(run_command(["envelope", "subject", "type", "cbor", hex]).decode().strip())

    @classmethod
    def from_known_value(cls, value: int | str):
        """
        Creates an envelope with a known value subject.
        """
        return cls(run_command(["envelope", "subject", "type", "known", str(value)]).decode().strip())

    @classmethod
    def from_assertion_pred_obj(cls, pred_type: str, pred_value: int | str, obj_type: str, obj_value: int | str):
        """
        Creates an assertion envelope with the given predicate and object.

        See the `envelope` command-line tool for the list of valid predicate and
        object types.
        """
        return cls(run_command(["envelope", "subject", "assertion", pred_type, str(pred_value), obj_type, str(obj_value)]).decode().strip())

    @classmethod
    def from_ssh_private_key(cls, private_key: SSHPrivateKey):
        """
        Creates an envelope with an SSH private key subject.
        """
        e: Envelope = cls.from_tagged_string(ssh_private_key_tag, private_key.pem_string)\
            .add_string_int_assertion("keySize", private_key.key_size)\
            .add_string_string_assertion("fingerprint", private_key.fingerprint)\
            .add_string_string_assertion("type", private_key.type_name)

        if private_key.comment:
            e = e.add_string_string_assertion("comment", private_key.comment)

        return e

    def to_ssh_private_key(self) -> SSHPrivateKey:
        """
        Extracts the subject of the envelope as an SSH private key.

        :raises ValueError: If the subject is not a valid SSH private key.
        """
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_private_key_tag:
            return SSHPrivateKey.from_pem_string(value)
        else:
            raise ValueError("Invalid SSH private key")

    @classmethod
    def from_ssh_public_key(cls, public_key: SSHPublicKey):
        """
        Creates an envelope with an SSH public key subject.
        """
        return cls.from_tagged_string(ssh_public_key_tag, public_key.string)

    def to_ssh_public_key(self) -> SSHPublicKey:
        """
        Extracts the subject of the envelope as an SSH public key.

        :raises ValueError: If the subject is not a valid SSH public key.
        """
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_public_key_tag:
            return SSHPublicKey.from_string(value)
        else:
            raise ValueError("Invalid SSH public key")

    @classmethod
    def from_ssh_signature(cls, signature: SSHSignature):
        """
        Creates an envelope with an SSH signature subject.
        """
        return cls.from_tagged_string(ssh_signature_tag, signature.pem_string)

    def to_ssh_signature(self) -> SSHSignature:
        """
        Extracts the subject of the envelope as an SSH signature.

        :raises ValueError: If the subject is not a valid SSH signature.
        """
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_signature_tag:
            return SSHSignature.from_pem_string(value)
        else:
            raise ValueError("Invalid SSH signature")

    def to_maybe_ssh_signature(self) -> SSHSignature | None:
        """
        Extracts the subject of the envelope as an SSH signature.

        Returns None if the subject is not a valid SSH signature.
        """
        try:
            return self.to_ssh_signature()
        except ValueError:
            return None

    @classmethod
    def from_ssh_object(cls, ssh_object: SSHPrivateKey | SSHPublicKey | SSHSignature):
        """
        Creates an envelope with an SSH object subject.

        The subject can be an SSH private key, SSH public key, or SSH signature.

        :raises ValueError: If the SSH object is invalid.
        """
        if isinstance(ssh_object, SSHPrivateKey):
            return cls.from_ssh_private_key(ssh_object)
        elif isinstance(ssh_object, SSHPublicKey):
            return cls.from_ssh_public_key(ssh_object)
        elif isinstance(ssh_object, SSHSignature):
            return cls.from_ssh_signature(ssh_object)
        else:
            raise ValueError("Invalid SSH object")

    def to_ssh_object(self) -> SSHPrivateKey | SSHPublicKey | SSHSignature:
        """
        Extracts the subject of the envelope as an SSH object.

        :raises ValueError: If the subject is not a valid SSH object.
        """
        tag, value = self.extract_tagged_cbor_subject()
        if tag == ssh_private_key_tag:
            return SSHPrivateKey.from_pem_string(value)
        elif tag == ssh_public_key_tag:
            return SSHPublicKey.from_string(value)
        elif tag == ssh_signature_tag:
            return SSHSignature.from_pem_string(value)
        else:
            raise ValueError("Invalid SSH object")

    def add_assertion(self: Self, pred: Self, obj: Self) -> Self:
        """
        Adds an assertion to the envelope.

        The returned envelope will have a new assertion with the given predicate
        and object.

        :param pred: The predicate of the assertion.
        :param obj: The object of the assertion.
        :return: The envelope with the new assertion.
        """
        return self.__class__(run_command(["envelope", "assertion", "add", "pred-obj", "envelope", pred.ur, "envelope", obj.ur, self.ur]).decode().strip())

    def add_string_string_assertion(self: Self, pred: str, obj: str) -> Self:
        """
        Adds an assertion with string predicate and object to the envelope.

        The returned envelope will have a new assertion with the given predicate
        and object.

        :param pred: The predicate of the assertion.
        :param obj: The object of the assertion.
        :return: The envelope with the new assertion.
        """
        return self.__class__(run_command(["envelope", "assertion", "add", "pred-obj", "string", pred, "string", obj, self.ur]).decode().strip())

    def add_string_int_assertion(self: Self, pred: str, obj: int) -> Self:
        """
        Adds an assertion with string predicate and integer object to the envelope.

        The returned envelope will have a new assertion with the given predicate
        and object.

        :param pred: The predicate of the assertion.
        :param obj: The object of the assertion.
        :return: The envelope with the new assertion.
        """
        return self.__class__(run_command(["envelope", "assertion", "add", "pred-obj", "string", pred, "number", str(obj), self.ur]).decode().strip())

    def wrapped(self):
        """
        Returns the wrapped envelope.
        """
        return self.__class__(run_command(["envelope", "subject", "type", "wrapped", self.ur]).decode().strip())

    def extract_tagged_cbor_subject(self) -> tuple[int, Any]:
        """
        Extracts the subject of the envelope as a CBOR-tagged value.

        Returns a tuple of the tag and value of the CBOR-tagged subject.

        Fails if the subject is not a CBOR-tagged value.
        """
        hex = run_command(["envelope", "extract", "cbor", self.ur]).decode()
        return extract_cbor_tag_and_value(bytes.fromhex(hex))

    def add_signature(self: Self, private_key: Self, namespace: str | None = None) -> Self:
        """
        Sign the envelope's subject with the given private key.

        The returned envelope will have a new `verifiedBy` assertion with the
        signature.

        :param private_key: The private key to sign the envelope with.
        :param namespace: The namespace for the signature.
        :return: The signed envelope.
        """
        # We're going to sign the digest of the envelope's subject, not the whole envelope
        digest = self.subject.digest
        # Convert the private key envelope to an SSH private key
        ssh_private_key = private_key.to_ssh_private_key()
        # Sign the digest
        ssh_signature = sign_message(digest, ssh_private_key, namespace)
        # Convert the SSH signature to an envelope
        signature = Envelope.from_ssh_signature(ssh_signature)
        # Add the signature to the envelope
        return self.add_assertion(self.from_known_value("verifiedBy"), signature)

    def verify_signature(self: Self, public_key: Self, namespace: str | None = None) -> bool:
        """
        Verify the envelope with the given public key.

        All `verifiedBy` assertions with SSH signatures on the envelope will be
        checked. If any of the signatures are valid, this method will return
        True.

        :param public_key: The public key to verify the envelope with.
        :param namespace: The namespace for the signature.
        :return: True if the envelope is verified by the public key, False
            otherwise.
        """
        # Get the digest of the envelope's subject
        digest = self.subject.digest
        # Convert the public key envelope to an SSH public key
        ssh_public_key = public_key.to_ssh_public_key()
        # Get every SSH signature on the envelope
        signatures = self.find_signatures()
        # Return True if any of the signatures are valid
        return any(verify_message(digest, signature, ssh_public_key, namespace) for signature in signatures)

    def find_signatures(self) -> list[SSHSignature]:
        """
        Find all SSH signatures on the envelope.

        This method will return a list of all SSH signatures found in the
        `verifiedBy` assertions on the envelope. If an assertion's object is not
        a valid SSH signature, it will be ignored.
        """
        # Get every `verifiedBy` assertion
        signature_assertion_lines = run_command(["envelope", "assertion", "find", "predicate", "known", "verifiedBy", self.ur]).decode()
        # Get the object of each `verifiedBy` assertion
        signature_objects = [self.__class__(line.strip()).object for line in signature_assertion_lines.splitlines()]
        # Convert each object to an SSH signature, or None if it's not a valid SSH signature
        maybe_signatures = [signature_object.to_maybe_ssh_signature() for signature_object in signature_objects]
        # Filter out the None values
        return [signature for signature in maybe_signatures if signature is not None]
