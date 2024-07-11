# `ssh_envelope`

## A Python command line tool for signing and verifying Gordian Envelopes using SSH keys.

<!--Guidelines: https://github.com/BlockchainCommons/secure-template/wiki -->

### _by Wolf McNally, Blockchain Commons_

**NOTE:** This repo is now **deprecated**. It has been superseded by the [Gordian Envelope CLI tool](https://github.com/BlockchainCommons/bc-envelope-cli-rust).

## Installation

Ensure you have OpenSSH and the `ssh-keygen` command-line tool installed on your system.

```shell
$ ssh -V
OpenSSH_9.6p1, LibreSSL 3.3.6
$ which ssh-keygen
/usr/bin/ssh-keygen
```

Optional: Install and activate a Python virtual environment (example using [conda](https://conda.io/projects/conda/en/latest/user-guide/getting-started.html)):

```shell
$ conda create --name ssh_envelope python=3.12
$ conda activate ssh_envelope

# When you do this your prompt should change to show the active environment:
(ssh_envelope) $
```

Ensure you have Python 3.x installed on your system.

```shell
$ python --version
Python 3.12.2
```

> 🍎 (Mac): If you don't have Python 3 installed, [`brew pyenv` and use that to install and set your global Python](https://www.freecodecamp.org/news/how-to-install-python-3-on-mac-and-update-the-python-version-macos-homebrew-command-guide/).

Ensure you have the [Rust](https://www.rust-lang.org/learn/get-started) `envelope` command-line tool, version 0.7.2 or later installed:

```shell
$ cargo install bc-envelope-cli
$ envelope --version
bc-envelope-cli 0.7.2
```

> 🍎 (Mac): If you don't have `cargo`, you can `brew rust`.

Clone the repository, and navigate to the project directory:

```shell
$ git clone https://github.com/BlockchainCommons/ssh-envelope-python.git
$ cd ssh-envelope-python
```

Install the tool and its dependencies:

```shell
$ pip install .
```

> 🍎 (Mac): If you also use Xcode on an M1, you may still have issues with your python environment. If all fails, use `pyenv exec pip install .` instead.

Optional, instead of previous step: For a developer install of the `ssh_envelope` tool, run the following:

```shell
$ pip install -e .
```

Verify the installation by running:

```shell
$ ssh_envelope --version
```

## Example

Note that this sequence uses both the Rust `envelope` command line tool and the Python `ssh_envelope` tool. `envelope` is for general manipulation of Gordian Envelopes, while `ssh_envelope` is for working with SSH keys on envelopes. Note that `envelope` creates and verifies Schnorr signatures, while `ssh_envelope` creates and verifies SSH signatures, so you need to use the correct tool for the type of signature you are working with.

```shell
# Create a subject to sign.
SUBJECT=`envelope subject type string 'Hello, world!'`
WRAPPED_SUBJECT=`envelope subject type wrapped $SUBJECT`

# Import the first signer.
# NOTE: This key is encrypted, so you will be asked for the password: `test`.
PRIVATE_KEY_1=`ssh_envelope import --object-path objects/test_ed25519`
PUBLIC_KEY_1=`ssh_envelope public --key $PRIVATE_KEY_1`

# Generate the second signer.
# We're assigning a custom comment to this key.
# Comments may not contain spaces.
PRIVATE_KEY_2=`ssh_envelope generate --comment "second-key"`
PUBLIC_KEY_2=`ssh_envelope public --key $PRIVATE_KEY_2`

# Sign the subject with the two signers.
SIGNED_ENVELOPE=`ssh_envelope add-signature --key $PRIVATE_KEY_1 --envelope $WRAPPED_SUBJECT`
SIGNED_ENVELOPE=`ssh_envelope add-signature --key $PRIVATE_KEY_2 --envelope $SIGNED_ENVELOPE`

# Verify both signatures.
# The `--silent` option suppresses output of the verified envelope.
ssh_envelope verify-signature --key $PUBLIC_KEY_1 --envelope $SIGNED_ENVELOPE --silent
ssh_envelope verify-signature --key $PUBLIC_KEY_2 --envelope $SIGNED_ENVELOPE --silent

# Create an unrelated signer.
PRIVATE_KEY_3=`ssh_envelope generate`
PUBLIC_KEY_3=`ssh_envelope public --key $PRIVATE_KEY_3`

# Fail to verify the signature with the unrelated signer.
ssh_envelope verify-signature --key $PUBLIC_KEY_3 --envelope $SIGNED_ENVELOPE
```

## Examining the Envelopes

We examine the contents of the envelopes created in the example above.

### Private Key

```shell
$ envelope format $PRIVATE_KEY_1
```

```
SSHPrivateKey [
    "comment": "wolf@Wolfs-MacBook-Pro.local"
    "fingerprint": "SHA256:wonJHWbmVYaZyry76VO/QM50PRqBKbFB1y3oBAGRtuY"
    "keySize": 256
    "type": "ED25519"
]
```

- The subject of the envelope is `SSHPrivateKey`, which is the private key itself, a tagged CBOR version of the textual, PEM-encoded private key.
- The assertions are all extracted from the key pair: the key's comment, fingerprint, key size, and type.

### Public Key

```shell
$ envelope format $PUBLIC_KEY_1
```

```
SSHPublicKey [
    "comment": "wolf@Wolfs-MacBook-Pro.local"
    "fingerprint": "SHA256:wonJHWbmVYaZyry76VO/QM50PRqBKbFB1y3oBAGRtuY"
    "keySize": 256
    "type": "ED25519"
]
```

- The only visible difference is that the subject is `SSHPublicKey`.

### Signed Envelope

```shell
$ envelope format $SIGNED_ENVELOPE
```

```
{
    "Hello, world!"
} [
    'verifiedBy': SSHSignature [
        "hashAlgorithm": "SHA512"
        "keyType": "ED25519"
        "namespace": "envelope"
    ]
    'verifiedBy': SSHSignature [
        "hashAlgorithm": "SHA512"
        "keyType": "ED25519"
        "namespace": "envelope"
    ]
]
```

- The subject is a wrapped envelope containing only a string as the subject. It could contain anything, including a different type of subject, carrying its own additional assertions.
- Each `verifiedBy` assertion has as its object an `SSHSignature` object, which is a CBOR-tagged PEM-encoded signature, as produced by `ssh-keygen`.
- The signature carries additional assertions with extracted metadata.
- The signature is over the digest of the subject, which is the wrapped envelope. This means that the envelope or any part of it could be elided without invalidating the signatures.
- The default signing namespace is `envelope`. When signing, you can specify this with the `--namespace` option.

## User Guide

- For input options where the input is provided on the command line, the pattern is (for example) `--key` or `-k`.
- If you wish to read the same input from a file, the pattern is `--key-path` or `-K`.
- If the input is required and you wish to read it from standard input, don't specify the option.

### Import

- Converts an SSH object (private key, public key, or signature) to an envelope.
- If the object is an encrypted private key, the password is requested, and the unencrypted private key is used to create the envelope.

```shell
$ ssh_envelope import --object-path objects/test_ed25519
```

```
ur:envelope/...
```

- You can also use the `--object` option to provide the input object on the command line.

```shell
$ ssh_envelope import --object "$(cat objects/test_ed25519.pub)"
```

```
ur:envelope/...
```

- If no object is provided on the command line, it is read from standard input.

```shell
$ ssh_envelope import < objects/test_ed25519_unencrypted
```

```
ur:envelope/...
```

### Export

- Converts an envelope (private key, public key, or signature) back to an SSH object.

```shell
$ ssh_envelope export --envelope $PRIVATE_KEY_1
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

### Generate Private Key

- Generates a new Ed25519 private key and returns it as an envelope.

```shell
$ ssh_envelope generate
```

```
ur:envelope/...
```

### Derive Public Key

- Derives the public key from a private key and returns it as an envelope.

```shell
$ ssh_envelope public --key $PRIVATE_KEY_1
```

```
ur:envelope/...
```

### Add Signature to Envelope

- Adds a signature to an envelope.
- Signs the digest of the envelope's subject. Per usual, does not sign the envelope's existing assertions unless you wrap it first.
- Adds a `'verifiedBy': SSHSignature` assertion to the envelope's assertions and returns the updated envelope.

```shell
$ ssh_envelope add-signature --key $PRIVATE_KEY_1 --envelope $WRAPPED_SUBJECT
```

```
ur:envelope/...
```

### Verify Signature

- Verifies a signature on an envelope.
- Requires a public key to verify the signature.
- Checks all signatures on the envelope and succeeds if any of them are valid.
- By default, returns the original envelope on success, which can be suppressed with the `--silent` option.
- Returns exit code 0 on success and 1 on failure.

```shell
$ ssh_envelope verify-signature --key $PUBLIC_KEY_1 --envelope $SIGNED_ENVELOPE
```

```
ur:envelope/...

```shell
$ ssh_envelope verify-signature --key $PUBLIC_KEY_1 --envelope $SIGNED_ENVELOPE --silent # prints nothing
```

```shell
$ ssh_envelope verify-signature --key $PUBLIC_KEY_3 --envelope $SIGNED_ENVELOPE # Fails with exit code 1
```

```
Signature verification failed
```

## `ssh-keygen` Cookbook

This section contains recipies for interacting with `ssh-keygen`.

### Generate ED25519 Key Pair

- Asks for a password to encrypt the private key. If no password is desired, enter an empty password.
- The public key is saved in a file with the same name as the private key, but with a `.pub` extension.

```shell
$ ssh-keygen -t ed25519 -f test_ed25519_encrypted
```

### Change or Remove the Password from a Private Key

- We copy the file because the commmand verwrites the existing file with the new file that has the new password (or no password).

```shell
$ cp test_ed25519_encrypted test_ed25519_unencrypted
$ ssh-keygen -p -f test_ed25519_unencrypted
```

### Extract the Public Key from a Private Key

```shell
$ ssh-keygen -y -f test_ed25519_encrypted > test_ed25519.pub
```

### Sign a File

```shell
$ ssh-keygen -Y sign -f test_ed25519_unencrypted -n file < example_data.txt > example_data.txt.sig
```

### Create an `allowed_signers` File from a Public Key

```shell
$ awk '{print $3 " " $1 " " $2}' test_ed25519.pub > allowed_signers
```

### Verify a File

```shell
$ ssh-keygen -Y verify -f allowed_signers -I wolf@Wolfs-MacBook-Pro.local -n file -s example_data.txt.sig < example_data.txt
```
