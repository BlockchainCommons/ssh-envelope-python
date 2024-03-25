## Dependencies

pip install -r requirements.txt

## Examples

### Import

- Converts an SSH object (private key, public key, or signature) to an envelope.
- If the object is an encrypted private key, the password is requested, and the unencrypted private key is used to create the envelope.

```shell
ssh_envelope import --file objects/test_ed25519_encrypted
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
