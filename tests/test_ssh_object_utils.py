from ssh_envelope.envelope_utils import export_ssh_object, format_envelope
from ssh_envelope.ssh_object_utils import generate_ed25519_private

key_envelope = generate_ed25519_private()
print(key_envelope)
print(format_envelope(key_envelope))
print(export_ssh_object(key_envelope))
