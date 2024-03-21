## Dependencies

pip install bcrypt cryptography


## Helpful Commands

### Generate ED25519 Key Pair

```sh
ssh-keygen -t ed25519 -f test_ed25519_encrypted
```

### Change or Remove the Password from a Private Key

Overwrites the existing file with the new file that has no password.

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
