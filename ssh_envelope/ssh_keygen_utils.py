import os
import tempfile
from typing import Optional

from ssh_envelope.envelope_utils import export_ssh_object
from ssh_envelope.file_utils import secure_delete
from ssh_envelope.run_command import run_command

def sign_data(private_key_envelope: str, message: bytes, namespace: str = "file") -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        private_key_file = None
        message_file = None
        signature_file = None

        try:
            # Export the private key from the envelope
            private_key = export_ssh_object(private_key_envelope)

            # Write the private key to a temporary file
            private_key_file = os.path.join(tmpdir, "id")
            with open(private_key_file, "w") as f:
                f.write(private_key)

            # Write the message to a temporary file
            message_file = os.path.join(tmpdir, "message")
            with open(message_file, "wb") as f:
                f.write(message)

            # Run ssh-keygen to sign the message
            signature_file = os.path.join(tmpdir, "signature")
            run_command(["ssh-keygen", "-Y", "sign", "-f", private_key_file, "-n", namespace, "-s", signature_file, message_file])

            # Read the signature from the file
            with open(signature_file, "r") as f:
                signature = f.read()

            return signature

        except Exception as e:
            raise Exception(f"Failed to sign data: {str(e)}") from e

        finally:
            # Securely delete the temporary files
            for file in [private_key_file, message_file, signature_file]:
                secure_delete(file)
