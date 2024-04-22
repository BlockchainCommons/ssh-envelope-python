import logging
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.serialization.ssh import SSHPrivateKeyTypes, SSHPublicKeyTypes;
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ssh_envelope.ssh_keygen_utils import extract_comment
from ssh_envelope.ssh_private_key import SSHPrivateKey
from ssh_envelope.ssh_public_key import SSHPublicKey
from ssh_envelope.ssh_signature import SSHSignature

from . import logconfig
__all__ = ['logconfig']

logger = logging.getLogger(__name__)

def import_ssh_object(string: str) -> SSHPrivateKey | SSHPublicKey | SSHSignature:
    import_functions = [import_signature, import_public_key, import_private_key]

    for import_func in import_functions:
        try:
            object = import_func(string)
            return object
        except Exception:
            pass

    raise ValueError("Failed to import SSH object")

def import_signature(string: str) -> SSHSignature:
    return SSHSignature.from_pem_string(string)

def import_public_key(string: str) -> SSHPublicKey:
    public_key = serialization.load_ssh_public_key(string.encode(), backend=default_backend())
    # return SSHPublicKey.from_string(serialize_public_key(public_key))
    return SSHPublicKey.from_string(string)

def import_private_key(string: str) -> SSHPrivateKey:
    input_data = string.encode()
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            if attempt == 1:
                logger.info("Attempting to load SSH key without password")
                private_key = load_private_key(input_data)
                logger.info("SSH key loaded successfully without password")
                return SSHPrivateKey.from_pem_string(string)
            else:
                logger.info(f"Attempt {attempt}/{max_attempts}: Prompting for password")
                password = getpass("Enter the password for the SSH key: ").encode()
                private_key = load_private_key(input_data, password=password)
                logger.info("SSH key loaded successfully with password")
                return SSHPrivateKey.from_pem_string(serialize_private_key(private_key))
        except ValueError as e:
            if "SSH key is password-protected." in str(e):
                logger.info("SSH key is password-protected, prompting for password")
            elif "Incorrect password provided for the SSH key." in str(e):
                logger.error(f"Incorrect password provided for the SSH key (attempt {attempt}/{max_attempts})")
                if attempt == max_attempts:
                    logger.error("Maximum password attempts reached.")
                    raise ValueError("Failed to load SSH key: maximum password attempts reached.")
            else:
                raise
    raise ValueError("Failed to load SSH key.")

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

def generate_ed25519_private() -> SSHPrivateKey:
    # Generate a new Ed25519 private key
    private_key = Ed25519PrivateKey.generate()

    # Serialize the private key to OpenSSH format
    ssh_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    return SSHPrivateKey.from_pem_string(ssh_private_key)

def derive_public_key(private_key_object: SSHPrivateKey) -> SSHPublicKey:
    # Load the private key
    private_key = load_ssh_private_key(private_key_object.pem_string.encode(), password=None, backend=default_backend())

    # Derive the public key
    public_key = private_key.public_key()

    # Serialize the public key to OpenSSH format
    ssh_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()

    key = SSHPublicKey.from_string(ssh_public_key)
    key.comment = private_key_object.comment
    return key
