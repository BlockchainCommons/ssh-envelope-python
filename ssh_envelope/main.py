#!python3

import sys
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.backends import default_backend
from getpass import getpass

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)

def load_private_key(private_key_data, password=None):
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

def read_private_key_file(path):
    try:
        with open(path, 'rb') as key_file:
            private_key_data = key_file.read()
        return private_key_data
    except FileNotFoundError:
        raise FileNotFoundError(f"SSH key file not found at path: {path}")
    except PermissionError:
        raise PermissionError(f"Permission denied while reading SSH key file: {path}")

def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

def handle_ssh_key(path):
    try:
        logger.info(f"Reading SSH key from file: {path}")
        private_key_data = read_private_key_file(path)

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                if attempt == 1:
                    logger.info("Attempting to load SSH key without password")
                    private_key = load_private_key(private_key_data)
                    logger.info("SSH key loaded successfully without password")
                    break
                else:
                    logger.info(f"Attempt {attempt}/{max_attempts}: Prompting for password")
                    password = getpass("Enter the password for the SSH key: ").encode()
                    private_key = load_private_key(private_key_data, password=password)
                    logger.info("SSH key loaded successfully with password")
                    break
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

        pem_key = serialize_private_key(private_key)
        sys.stdout.write(pem_key)
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Unexpected error occurred: {str(e)}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        logger.error("Usage: ssh_envelope <path_to_private_key>")
        sys.exit(1)
    key_path = sys.argv[1]
    handle_ssh_key(key_path)

if __name__ == "__main__":
    main()
