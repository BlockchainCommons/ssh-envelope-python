import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from ssh_envelope.ssh_private_key import SSHPrivateKey
from tests.test_data import ed25519_private_key

def test_ed25519_private_key():
    key = SSHPrivateKey.from_pem_string(ed25519_private_key)
    assert repr(key) == "SSHPrivateKey(type: ssh-ed25519, public_key_data: 0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, check_num: c90f110e, private_key_data: b6e2cd022947a7a79ded37ab4fe5d6678bdea762b60a8604984899e2455f130c0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, comment: wolf@Wolfs-MacBook-Pro.local)"
    assert key.pem_string == ed25519_private_key

test_ed25519_private_key()
