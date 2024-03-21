#!python3

import sys
import logging
from getpass import getpass

from ssh_envelope.utils import ssh_keys_utils

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)

def read_file(path):
    try:
        with open(path, 'rb') as key_file:
            data = key_file.read()
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found at path: {path}")
    except PermissionError:
        raise PermissionError(f"Permission denied while reading file: {path}")

def handle_ssh_key(path):
    try:
        logger.info(f"Reading SSH key from file: {path}")
        private_key_data = read_file(path)

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                if attempt == 1:
                    logger.info("Attempting to load SSH key without password")
                    private_key = ssh_keys_utils.load_private_key(private_key_data)
                    logger.info("SSH key loaded successfully without password")
                    break
                else:
                    logger.info(f"Attempt {attempt}/{max_attempts}: Prompting for password")
                    password = getpass("Enter the password for the SSH key: ").encode()
                    private_key = ssh_keys_utils.load_private_key(private_key_data, password=password)
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

        pem_key = ssh_keys_utils.serialize_private_key(private_key)
        return pem_key
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
    print(handle_ssh_key(key_path))

if __name__ == "__main__":
    main()
