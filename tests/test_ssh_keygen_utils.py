from ssh_envelope.envelope import Envelope
from ssh_envelope.ssh_keygen_utils import sign_message, verify_message
from ssh_envelope.ssh_object_utils import derive_public_key, generate_ed25519_private, import_ssh_object

example_ssh_private_key = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBbjElToppgA0e4gpy0u8DuRik88m1ggZGVpztneCqAYAAAAKDI/yjCyP8o
wgAAAAtzc2gtZWQyNTUxOQAAACBbjElToppgA0e4gpy0u8DuRik88m1ggZGVpztneCqAYA
AAAEA7//5KYvv6Fojiwq+KEhIxRmAdkxk5gMXL4spqzBgIM1uMSVOimmADR7iCnLS7wO5G
KTzybWCBkZWnO2d4KoBgAAAAHHdvbGZAV29sZnMtTWFjQm9vay1Qcm8ubG9jYWwB
-----END OPENSSH PRIVATE KEY-----
'''

example_private_key_envelope = 'ur:envelope/tpcstanehnkkadlsdpdpdpdpdpfwfeflgaglcxgwgdfeglgugufdcxgdgmgahffpghfecxgrfehkdpdpdpdpdpbkideofwjzidjtglknhsfxehjphthdjejyieimfefpfpfpfpfpfwfleckoidjngofpfpfpfpfeidjneskphtgyfpfpfpfpfpfpfpfpfpfwfpfpfpfpgtktfpfpfpfpjykniaeyiojyhthggykkglghgoksbkgwgyfpfpfpfxfwidimfejzghjljojoiofpdyiheeiojokkdykpetfykpgminjeetetjnehioiohtflhfjoknjyjtihfxjsfphkfpfpfpfpgaioknfljnjsiegtksjojsjtgyfpfpfpfpjykniaeyiojybkhthggykkglghgoksgwgyfpfpfpfxfwidimfejzghjljojoiofpdyiheeiojokkdykpetfykpgminjeetetjnehioiohtflhfjoknjyjtihfxjsfphkfpfpfpfpfefpemdldlecgrhkkokoenfgjliminbkktjsdngrfeisgaksgmjnfpiejeksjeeciogthdgseejkjojsknfwiogagtehkpgtguhfgwinjnjnfpfygmeminfxjtgsguemktgwecflgrghknkkidhgfxfwjehthgjtgweyieeegrjlfwiofpfpfpfpbkfpfpfefxfpktgyfgbkdpdpdpdpdpfeglfycxgwgdfeglgugufdcxgdgmgahffpghfecxgrfehkdpdpdpdpdpbkiyrovsat'

def test_sign():
    private_key_envelope = Envelope.from_ssh_object(import_ssh_object(example_ssh_private_key))
    message = b"hello"
    signature_envelope = Envelope.from_ssh_signature(sign_message(message, private_key_envelope.to_ssh_private_key()))
    public_key_envelope = Envelope.from_ssh_public_key(derive_public_key(private_key_envelope.to_ssh_private_key()))
    is_verified = verify_message(message, signature_envelope.to_ssh_signature(), public_key_envelope.to_ssh_public_key())
    assert(is_verified)
    is_verified = verify_message(b"wrong_message", signature_envelope.to_ssh_signature(), public_key_envelope.to_ssh_public_key())
    assert(not is_verified)

def test_wrap_and_sign_envelope():
    message_envelope = Envelope.from_string("Hello, world!")
    wrapped_envelope = message_envelope.wrapped()

    private_key = Envelope.from_ssh_private_key(generate_ed25519_private())
    signed_envelope = wrapped_envelope.sign(private_key)
    print(signed_envelope.format)

test_wrap_and_sign_envelope()
