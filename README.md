## Dependencies

pip install -r requirements.txt

## Examples

- For input options where the input is provided on the command line, the pattern is (for example) `--key` or `-k`.
- If you wish to read the same input from a file, the pattern is `--key-path` or `-K`.
- If the input is required and you wish to read it from standard input, don't specify the option.

### Import

- Converts an SSH object (private key, public key, or signature) to an envelope.
- If the object is an encrypted private key, the password is requested, and the unencrypted private key is used to create the envelope.

```shell
ssh_envelope import --object-path objects/test_ed25519_encrypted
```

- You can also use the `--object` option to provide the input object on the command line.

```shell
ssh_envelope import --object "$(cat objects/test_ed25519.pub)"
```

- If no object is provided on the command line, it is read from standard input.

```shell
ssh_envelope import < objects/test_ed25519_unencrypted
```

### Export

- Converts an envelope (private key, public key, or signature) back to an SSH object.

```shell
ssh_envelope export ur:envelope/...
```

### Generate Private Key

- Generates a new Ed25519 private key and returns it as an envelope.

```shell
ssh_envelope generate
```

### Derive Public Key

- Derives the public key from a private key and returns it as an envelope.

```shell
ssh_envelope public --key ur:envelope/...
```

### Sign Arbitrary Data

- Signs arbitrary data with a private key and returns the signature as an envelope.
- At least either the key or the message to be signed must be provided on the command line: they cannot both be read from standard input.

```shell
ssh_envelope sign-data --key ur:envelope/... < example_data.txt
```

### Add Signature to Envelope

- Adds a signature to an envelope.
- Signs the digest of the envelope's subject. Per usual, does not sign the envelope's existing assertions unless you wrap it first.
- Adds a `'verifiedBy': 40802(<SSH Signature>)` assertion to the envelope's assertions and returns the updated envelope.

```shell
ssh_envelope add-signature --key ur:envelope/... --envelope ur:envelope/...
```

## `ssh-keygen` Cookbook

### Generate ED25519 Key Pair

- Asks for a password to encrypt the private key. If no password is desired, enter an empty password.
- The public key is saved in a file with the same name as the private key, but with a `.pub` extension.

```sh
ssh-keygen -t ed25519 -f test_ed25519_encrypted
```

### Change or Remove the Password from a Private Key

- We copy the file because the commmand verwrites the existing file with the new file that has the new password (or no password).

```sh
cp test_ed25519_encrypted test_ed25519_unencrypted
ssh-keygen -p -f test_ed25519_unencrypted
```

### Extract the Public Key from a Private Key

```sh
ssh-keygen -y -f test_ed25519_encrypted > test_ed25519.pub
```

### Sign a File

```sh
ssh-keygen -Y sign -f test_ed25519_unencrypted -n file < example_data.txt > example_data.txt.sig
```

### Create an `allowed_signers` File from a Public Key

```sh
awk '{print $3 " " $1 " " $2}' test_ed25519.pub > allowed_signers
```

### Verify a File

```sh
ssh-keygen -Y verify -f allowed_signers -I wolf@Wolfs-MacBook-Pro.local -n file -s example_data.txt.sig < example_data.txt
```
