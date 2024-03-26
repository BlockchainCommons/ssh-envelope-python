import os
import tempfile

from ssh_envelope.envelope import Envelope
from ssh_envelope.file_utils import secure_delete
from ssh_envelope.run_command import run_command
from ssh_envelope.ssh_object_utils import import_signature
from ssh_envelope.ssh_private_key import SSHPrivateKey

default_namespace = "file"

def sign_message(message: bytes, private_key_envelope: Envelope, namespace: str | None = None) -> Envelope:
    with tempfile.TemporaryDirectory() as tmpdir:
        private_key_file = None

        try:
            # Export the private key from the envelope
            private_key: SSHPrivateKey = private_key_envelope.to_ssh_private_key()

            # Write the private key to a temporary file
            private_key_file = os.path.join(tmpdir, "id")
            with open(private_key_file, "w") as f:
                f.write(private_key.pem)

            # Set appropriate permissions on the private key file
            os.chmod(private_key_file, 0o600)

            # Run ssh-keygen to sign the message, passing the message via stdin
            namespace = namespace or default_namespace
            signature = run_command(["ssh-keygen", "-Y", "sign", "-f", private_key_file, "-n", namespace], stdin=message)

            # Import the signature into an envelope
            envelope = import_signature(signature.decode())
            if envelope is None:
                raise ValueError("Failed to import signature")
            return envelope

        except Exception as e:
            raise Exception(f"Failed to sign data: {str(e)}") from e

        finally:
            # Securely delete the temporary private key file
            secure_delete(private_key_file)

def verify_message(message: bytes, signature_envelope: Envelope, public_key_envelope: Envelope, namespace: str | None = None) -> bool:
    with tempfile.TemporaryDirectory() as tmpdir:
        signature_file = None
        allowed_signers_file = None

        try:
            # Extract the SSH signature from the envelope
            signature = signature_envelope.to_ssh_signature()

            # Write the signature to a temporary file
            signature_file = os.path.join(tmpdir, "signature.sig")
            with open(signature_file, "w") as f:
                f.write(signature.pem)

            # Extract the public key from the envelope
            public_key = public_key_envelope.to_ssh_public_key()

            # Extract the key type and base64-encoded key
            key_type = public_key.type
            key_base64 = public_key.base64
            identity = public_key.identity or "identity"
            namespace = namespace or default_namespace

            # Write the public key to a temporary file in the allowed_signers format
            allowed_signers_file = os.path.join(tmpdir, "allowed_signers")
            with open(allowed_signers_file, "w") as f:
                f.write(f"{identity} {key_type} {key_base64}\n")

            # Run ssh-keygen to verify the signature, passing the message via stdin
            try:
                run_command(["ssh-keygen", "-Y", "verify", "-f", allowed_signers_file, "-n", namespace, "-s", signature_file, "-I", identity], stdin=message)
                return True
            except:
                return False

        finally:
            # Securely delete the temporary files
            secure_delete(signature_file)
            secure_delete(allowed_signers_file)

def sign_envelope_digest(envelope: Envelope, private_key_envelope: Envelope, namespace: str | None = None) -> Envelope:
    return sign_message(envelope.digest, private_key_envelope, namespace)
