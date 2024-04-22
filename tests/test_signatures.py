import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from ssh_envelope.ssh_signature import SSHSignature
from tests.test_data import example_message_ed25519_signature

def test_ed25519_signature():
    sig = SSHSignature.from_pem_string(example_message_ed25519_signature)
    assert sig.pem_string == example_message_ed25519_signature

# test_ed25519_signature()
