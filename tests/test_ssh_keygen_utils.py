from ssh_envelope.ssh_keygen_utils import sign_message, verify_message
from ssh_envelope.ssh_object_utils import derive_public_key, import_ssh_object

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
    private_key_envelope = import_ssh_object(example_ssh_private_key)
    message = b"hello"
    signature_envelope = sign_message(message, private_key_envelope)
    public_key_envelope = derive_public_key(private_key_envelope)
    is_verified = verify_message(message, signature_envelope, public_key_envelope)
    assert(is_verified)
    is_verified = verify_message(b"wrong_message", signature_envelope, public_key_envelope)
    assert(not is_verified)
