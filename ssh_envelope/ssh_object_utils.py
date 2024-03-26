import logging
import sys
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.serialization.ssh import SSHPrivateKeyTypes, SSHPublicKeyTypes;
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ssh_envelope.envelope import Envelope

from .envelope_utils import export_private_key, ssh_private_key_envelope, ssh_public_key_envelope

from . import logconfig
__all__ = ['logconfig']

from .envelope_utils import ssh_private_key_envelope, ssh_public_key_envelope, ssh_signature_envelope

logger = logging.getLogger(__name__)

def import_ssh_object(string: str) -> Envelope:
    input_data = string.encode()
    object_envelope = import_signature(input_data)
    if object_envelope is None:
        object_envelope = import_public_key(input_data)
    if object_envelope is None:
        object_envelope = import_private_key(input_data)
    if object_envelope is None:
        raise ValueError("Failed to import SSH object")
    return object_envelope

def import_signature(input_data: bytes) -> Envelope | None:
    if b"BEGIN SSH SIGNATURE" in input_data:
        envelope = ssh_signature_envelope(input_data.decode())
        return envelope
    else:
        return None

def import_public_key(input_data: bytes) -> Envelope | None:
    try:
        public_key = serialization.load_ssh_public_key(input_data, backend=default_backend())
        pem_key = serialize_public_key(public_key)
        envelope = ssh_public_key_envelope(pem_key)
        return envelope
    except:
        return None

def import_private_key(input_data: bytes) -> Envelope | None:
    try:
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                if attempt == 1:
                    logger.info("Attempting to load SSH key without password")
                    private_key = load_private_key(input_data)
                    logger.info("SSH key loaded successfully without password")
                    pem_key = serialize_private_key(private_key)
                    envelope = ssh_private_key_envelope(pem_key)
                    return envelope
                else:
                    logger.info(f"Attempt {attempt}/{max_attempts}: Prompting for password")
                    password = getpass("Enter the password for the SSH key: ").encode()
                    private_key = load_private_key(input_data, password=password)
                    logger.info("SSH key loaded successfully with password")
                    pem_key = serialize_private_key(private_key)
                    envelope = ssh_private_key_envelope(pem_key)
                    return envelope
            except ValueError as e:
                if "SSH key is password-protected." in str(e):
                    logger.info("SSH key is password-protected, prompting for password")
                elif "Incorrect password provided for the SSH key." in str(e):
                    logger.error(f"Incorrect password provided for the SSH key (attempt {attempt}/{max_attempts})")
                    if attempt == max_attempts:
                        logger.error("Maximum password attempts reached. Exiting.")
                        sys.exit(1)
                else:
                    raise
    except:
        return None


def load_private_key(private_key_data: bytes, password: bytes | None = None) -> SSHPrivateKeyTypes:
    try:
        private_key = load_ssh_private_key(private_key_data, password=password, backend=default_backend())
        return private_key
    except ValueError as e:
        if 'key is password-protected' in str(e).lower():
            raise ValueError("SSH key is password-protected.")
        elif 'corrupt data: broken checksum' in str(e).lower():
            raise ValueError("Incorrect password provided for the SSH key.")
        else:
            raise ValueError(f"Failed to decrypt the SSH key or unsupported key format: {str(e)}")

def serialize_private_key(private_key: SSHPrivateKeyTypes) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

def serialize_public_key(public_key: SSHPublicKeyTypes) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    return pem.decode()

def generate_ed25519_private() -> Envelope:
    """
    Generates a new Ed25519 private key, serializes it to OpenSSH format, and encapsulates it in a Gordian envelope.

    Returns:
        str: The Gordian envelope containing the serialized Ed25519 private key.
    """
    # Generate a new Ed25519 private key
    private_key = Ed25519PrivateKey.generate()

    # Serialize the private key to OpenSSH format
    ssh_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Encapsulate the serialized private key in a Gordian envelope
    envelope = ssh_private_key_envelope(ssh_private_key)

    return envelope

def derive_public_key(private_key_envelope: Envelope) -> Envelope:
    """
    Extracts the SSH private key from the given envelope, derives the corresponding
    public key, serializes it to OpenSSH format, and encapsulates it in a new envelope.

    Args:
        private_key_envelope (str): The envelope containing the SSH private key.

    Returns:
        str: The envelope containing the derived SSH public key.
    """
    # Extract the private key from the envelope
    private_key_string = export_private_key(private_key_envelope)

    # Load the private key object
    private_key = load_ssh_private_key(private_key_string.encode(), password=None, backend=default_backend())

    # Derive the public key
    public_key = private_key.public_key()

    # Serialize the public key to OpenSSH format
    ssh_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')

    # Encapsulate the serialized public key in a new envelope
    public_key_envelope = ssh_public_key_envelope(ssh_public_key)

    return public_key_envelope
