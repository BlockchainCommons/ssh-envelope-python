import os
import tempfile
from typing import Optional

from ssh_envelope.envelope_utils import export_ssh_object
from ssh_envelope.file_utils import secure_delete
from ssh_envelope.run_command import run_command
from ssh_envelope.ssh_object_utils import import_signature

def sign_data(private_key_envelope: str, message: bytes, namespace: str = "file") -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        private_key_file = None

        try:
            # Export the private key from the envelope
            private_key = export_ssh_object(private_key_envelope)

            # Write the private key to a temporary file
            private_key_file = os.path.join(tmpdir, "id")
            with open(private_key_file, "w") as f:
                f.write(private_key)

            # Set appropriate permissions on the private key file
            os.chmod(private_key_file, 0o600)

            # Run ssh-keygen to sign the message, passing the message via stdin
            signature = run_command(["ssh-keygen", "-Y", "sign", "-f", private_key_file, "-n", namespace], stdin=message)

            # Import the signature into an envelope
            envelope = import_signature(signature)
            if envelope is None:
                raise ValueError("Failed to import signature")
            return envelope

        except Exception as e:
            raise Exception(f"Failed to sign data: {str(e)}") from e

        finally:
            # Securely delete the temporary private key file
            secure_delete(private_key_file)
