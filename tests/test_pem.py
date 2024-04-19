from ssh_envelope.pem import PEM

encrypted_private_key = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAAFiGpGp
tFlJLG9vpkh+AcAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIFuMSVOimmADR7iC
nLS7wO5GKTzybWCBkZWnO2d4KoBgAAAAoOtDEwxXcRHJWAxcYY5iJVdBCl5UGfLYYPK+Gb
ybsn7Oz1WlEL4RVorR854HqXRwch5BQ5d3KXYm5vEj5kiu4cHLOHqkFoSRrwY7F7yOwgYr
fNPS6xZvrhxx2spEtB95QROjGbgjEa1tNI4vXYArmK70tlpaEgsFMLfuXVZmlUZZS2M2eh
2L7leSuWLZDPVlVSsNqEXD/bVVGHGw3c1Tf8Y=
-----END OPENSSH PRIVATE KEY-----
"""

example = """
-----BEGIN EXAMPLE-----
dGVzdA==
-----END EXAMPLE-----
"""

def test_decode_pem():
    pem = PEM.from_pem_string(encrypted_private_key)
    assert(pem.header == "OPENSSH PRIVATE KEY")
    assert(len(pem.data) == 290)

def test_encode_pem():
    pem = PEM.from_header_and_data("EXAMPLE", b"test")
    assert(pem.header == "EXAMPLE")
    assert(pem.data == b"test")
    assert(pem.pem_string.strip() == example.strip())
    pem2 = PEM.from_pem_string(example)
    assert(pem == pem2)

# test_decode_pem()
# test_encode_pem()
