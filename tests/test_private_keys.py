from ssh_envelope.ssh_private_key import SSHPrivateKey
from test_data import ed25519_private_key;

def test_ed25519_private_key():
    key = SSHPrivateKey(ed25519_private_key)
    assert repr(key) == "SSHPrivateKey(type: ssh-ed25519, public_key_data: 0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, check_num: c90f110e, private_key_data: b6e2cd022947a7a79ded37ab4fe5d6678bdea762b60a8604984899e2455f130c0f2954f7a55e51303fe401d241f7bcb31495411ce66a09dfd9ed626721facde0, comment: wolf@Wolfs-MacBook-Pro.local)"
    assert key.pem_string.strip() == ed25519_private_key.strip()

test_ed25519_private_key()
