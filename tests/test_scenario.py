import io
from contextlib import redirect_stdout, redirect_stderr

from ssh_envelope.envelope import Envelope
from ssh_envelope.run_command import run_command
from ssh_envelope.main import _main

def run(args: list[str]) -> str:
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
        _main(args)

    stdout = stdout_capture.getvalue().strip()
    stderr = stderr_capture.getvalue().strip()

    return '\n'.join(filter(None, [stdout, stderr])) if stderr else stdout

def test_scenario():
    # Create a subject to sign
    subject = Envelope.from_string("Hello, world!")
    wrapped_subject = subject.wrapped()

    # Import the first signer. This key is encrypted, so you will be asked for the password, `test`.
    private_key_1 = Envelope(run(["import", "--object-path", "objects/test_ed25519_unencrypted"]))
    public_key_1 = Envelope(run(["public", "--key", private_key_1.ur]))

    # Generate the second signer. We're assigning a custom comment to this key. Comments may not contain spaces.
    private_key_2 = Envelope(run(["generate", "--comment", "second-key"]))
    public_key_2 = Envelope(run(["public", "--key", private_key_2.ur]))

    # Sign the subject with the two signers
    signed_envelope = Envelope(run(["add-signature", "--key", private_key_1.ur, "--envelope", wrapped_subject.ur]))
    signed_envelope = Envelope(run(["add-signature", "--key", private_key_2.ur, "--envelope", signed_envelope.ur]))

    # Verify both signatures
    verified_1 = run(["verify-signature", "--key", public_key_1.ur, "--envelope", signed_envelope.ur])
    assert verified_1 == "True"
    verified_2 = run(["verify-signature", "--key", public_key_2.ur, "--envelope", signed_envelope.ur])
    assert verified_2 == "True"

    # Create an unrelated signer
    private_key_3 = Envelope(run(["generate"]))
    public_key_3 = Envelope(run(["public", "--key", private_key_3.ur]))

    # Fail to verify the signature with the unrelated signer
    verified_3 = run(["verify-signature", "--key", public_key_3.ur, "--envelope", signed_envelope.ur])
    assert verified_3 == "False"

# test_scenario()
