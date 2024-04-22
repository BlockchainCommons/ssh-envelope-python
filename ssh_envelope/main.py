#
# main.py
#

import logging
import argparse
import sys

from ssh_envelope import logconfig
from ssh_envelope.ssh_private_key import SSHPrivateKey
from ssh_envelope.ssh_public_key import SSHPublicKey
from ssh_envelope.version import __version__
__all__ = ['logconfig']

from ssh_envelope.envelope import Envelope
from ssh_envelope.ssh_keygen_utils import extract_comment_from_path, sign_message

from ssh_envelope.ssh_object_utils import derive_public_key, generate_ed25519_private, import_ssh_object

logger = logging.getLogger(__name__)


def read_envelope(args) -> Envelope:
    envelope: Envelope | None = None
    if args.envelope:
        logger.info("Reading envelope from --envelope")
        envelope = Envelope(args.envelope)
    elif args.envelope_path:
        logger.info("Reading envelope from --envelope-path")
        with open(args.envelope_path, 'r') as file:
            envelope = Envelope(file.read())
    else:
        logger.info("Reading envelope from stdin")
        envelope = Envelope(sys.stdin.read())
    return envelope


def read_private_key(args) -> Envelope:
    key: Envelope | None = None
    if args.key:
        logger.info("Reading private key from --key")
        key = Envelope(args.key)
    elif args.key_path:
        logger.info("Reading private key from --key-path")
        with open(args.key_path, 'r') as file:
            key = Envelope(file.read())
    else:
        logger.info("Reading private key from stdin")
        key = Envelope(sys.stdin.read())
    return key


def read_public_key(args) -> Envelope:
    key: Envelope | None = None
    if args.key:
        logger.info("Reading public key from --key")
        key = Envelope(args.key)
    elif args.key_path:
        logger.info("Reading public key from --key-path")
        with open(args.key_path, 'r') as file:
            key = Envelope(file.read())
    else:
        logger.info("Reading public key from stdin")
        key = Envelope(sys.stdin.read())
    return key


def read_object_data(args) -> str:
    object_data = None
    if args.object:
        logger.info("Reading SSH object from --object")
        object_data = args.object
    elif args.object_path:
        logger.info("Reading SSH object from --object-path")
        with open(args.object_path) as file:
            object_data = file.read()
    else:
        logger.info("Reading SSH object from stdin")
        object_data = sys.stdin.read()
    return object_data


def import_command(args: argparse.Namespace):
    logger.info(f"Importing SSH object")
    object_data = read_object_data(args)
    object = import_ssh_object(object_data)
    if args.comment:
        if isinstance(object, SSHPrivateKey):
            object.comment = args.comment
        elif isinstance(object, SSHPublicKey):
            object.comment = args.comment
    # This is a workaround to set the comment on the private key object because
    # OpenSSH encrypted private key files do *not* contain a comment field, even
    # though a *decrypted* private key files and public key file do. When asked
    # to extract the comment from a private key file, ssh-keygen sneakily gets
    # it from the public key file if a sibling file exists with the same name
    # and a .pub extension. So if the user is importing an encrypted private key
    # from a file path, and we don't get a comment, then we're going to ask
    # ssh-keygen to do it.
    if isinstance(object, SSHPrivateKey)\
        and object.comment == ''\
        and args.object_path:
        object.comment = extract_comment_from_path(args.object_path)
    envelope = Envelope.from_ssh_object(object)
    sys.stdout.write(envelope.ur + '\n')


def export_command(args: argparse.Namespace):
    logger.info(f"Exporting object")
    envelope = read_envelope(args)
    object = envelope.to_ssh_object()
    sys.stdout.write(f"{object}" + '\n')


def generate_command(args: argparse.Namespace):
    logger.info(f"Generating Ed25519 private key")
    key = generate_ed25519_private()
    if args.comment:
        key.comment = args.comment
    envelope = Envelope.from_ssh_private_key(key)
    sys.stdout.write(envelope.ur + '\n')


def public_command(args: argparse.Namespace):
    logger.info(f"Deriving public key from private key")
    key = read_private_key(args)
    public_key_envelope = Envelope.from_ssh_public_key(derive_public_key(key.to_ssh_private_key()))
    sys.stdout.write(public_key_envelope.ur + '\n')


# def sign_data_command(args: argparse.Namespace):
#     logger.info(f"Signing data")

#     if not args.key and not args.key_path and not args.message and not args.message_path:
#         raise ValueError("At least one of the key envelope (--key or --key-path) or the message to be signed (--message or --message-path) must be provided on the command line: they cannot both be provided via stdin.")

#     key: Envelope | None = None
#     if args.key:
#         logger.info("Reading key from --key")
#         key = Envelope(args.key)
#     elif args.key_path:
#         logger.info("Reading key from --key-path")
#         with open(args.key_path, 'r') as file:
#             key = Envelope(file.read())
#     elif not args.message and not args.message_path:
#         logger.info("Reading key from stdin")
#         key = Envelope(sys.stdin.read())

#     message = None
#     if args.message:
#         logger.info("Reading message from --message")
#         message = args.message.encode()
#     elif args.message_path:
#         logger.info("Reading message from --message-path")
#         with open(args.message_path, 'rb') as file:
#             message = file.read()
#     elif not key:
#         logger.info("Reading message from stdin")
#         message = sys.stdin.buffer.read()

#     if not key:
#         raise ValueError("Key envelope not provided.")
#     if not message:
#         raise ValueError("Message to sign not provided.")

#     signature_envelope = Envelope.from_ssh_signature(sign_message(message, key.to_ssh_private_key(), args.namespace))
#     sys.stdout.write(signature_envelope.ur + '\n')

def add_signature_command(args: argparse.Namespace):
    logger.info(f"Adding signature to envelope")

    if not args.envelope and not args.envelope_path and not args.key and not args.key_path:
        raise ValueError("At least one of the envelope (--envelope or --envelope-path) or the key envelope (--key or --key-path) must be provided on the command line: they cannot both be provided via stdin.")

    key = read_private_key(args)
    envelope = read_envelope(args)
    signed_envelope = envelope.add_signature(key, namespace=args.namespace)
    sys.stdout.write(signed_envelope.ur + '\n')


def verify_signature_command(args: argparse.Namespace):
    logger.info(f"Verifying signature on envelope")

    if not args.envelope and not args.envelope_path and not args.key and not args.key_path:
        raise ValueError("At least one of the envelope (--envelope or --envelope-path) or the key envelope (--key or --key-path) must be provided on the command line: they cannot both be provided via stdin.")

    key = read_public_key(args)
    envelope = read_envelope(args)
    is_verified = envelope.verify_signature(key)
    if is_verified:
        if not args.silent:
            sys.stdout.write(f"{envelope.ur}\n")
    else:
        sys.stderr.write(f"Signature verification failed\n")
        sys.exit(1)


def _main(arg_array):
    if "--version" in arg_array:
        print(f"SSH Envelope version {__version__}")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Envelope/SSH Key Management Tool")
    subparsers = parser.add_subparsers(help='commands')

    # import_command
    parser_import = subparsers.add_parser('import', help='Convert an SSH object to an envelope')
    parser_import.add_argument('-o', '--object', help='SSH object as a string', default=None)
    parser_import.add_argument('-O', '--object-path', help='Path to the file containing the SSH object', default=None)
    parser_import.add_argument('-c', '--comment', help='Comment to add to the private or public key. Overrides any comment contained in the original object. Ignored for signatures.', default=None)
    parser_import.set_defaults(func=import_command)

    # export_command
    parser_export = subparsers.add_parser('export', help='Convert an envelope to an SSH object')
    parser_export.add_argument('-e', '--envelope', help='Envelope to export', default=None)
    parser_export.add_argument('-E', '--envelope-path', help='Path to the file containing the envelope', default=None)
    parser_export.set_defaults(func=export_command)

    # generate_command
    parser_generate = subparsers.add_parser('generate', help='Generate a new Ed25519 private key')
    parser_generate.add_argument('-c', '--comment', help='Comment to add to the private key', default=None)
    parser_generate.set_defaults(func=generate_command)

    # public_command
    parser_public = subparsers.add_parser('public', help='Derive a public key from a private key')
    parser_public.add_argument('-k', '--key', help='Private key envelope', default=None)
    parser_public.add_argument('-K', '--key-path', help='Path to the file containing the private key envelope', default=None)
    parser_public.set_defaults(func=public_command)

    # # sign_data_command
    # parser_sign = subparsers.add_parser('sign-data', help='Sign data with a private key')
    # parser_sign.add_argument('-k', '--key', help='Private key envelope', default=None)
    # parser_sign.add_argument('-K', '--key-path', help='Path to the file containing the private key envelope', default=None)
    # parser_sign.add_argument('-m', '--message', help='Message to sign', default=None)
    # parser_sign.add_argument('-M', '--message-path', help='Path to the file containing the message to sign', default=None)
    # parser_sign.add_argument('-n', '--namespace', help='Namespace for the signature', default='file')
    # parser_sign.set_defaults(func=sign_data_command)

    # add_signature_command
    parser_add_signature = subparsers.add_parser('add-signature', help='Add an SSH signature to an envelope. The digest of the subject is signed and a new `verifiedBy` assertion is added.')
    parser_add_signature.add_argument('-k', '--key', help='Private key envelope', default=None)
    parser_add_signature.add_argument('-K', '--key-path', help='Path to the file containing the private key envelope', default=None)
    parser_add_signature.add_argument('-e', '--envelope', help='Envelope to sign', default=None)
    parser_add_signature.add_argument('-E', '--envelope-path', help='Path to the file containing the envelope to sign', default=None)
    parser_add_signature.add_argument('-n', '--namespace', help='Namespace for the signature', default='envelope')
    parser_add_signature.set_defaults(func=add_signature_command)

    # verify_signature_command
    parser_verify_signature = subparsers.add_parser('verify-signature', help='Verify an SSH signature on an envelope.')
    parser_verify_signature.add_argument('-k', '--key', help='Public key envelope', default=None)
    parser_verify_signature.add_argument('-K', '--key-path', help='Path to the file containing the public key envelope', default=None)
    parser_verify_signature.add_argument('-e', '--envelope', help='Envelope to verify', default=None)
    parser_verify_signature.add_argument('-E', '--envelope-path', help='Path to the file containing the envelope to verify', default=None)
    parser_verify_signature.add_argument('-s', '--silent', help='Suppress output', default=False, action='store_true')
    parser_verify_signature.set_defaults(func=verify_signature_command)

    args = parser.parse_args(arg_array)
    if hasattr(args, 'func'):
        try:
            args.func(args)
        except Exception as e:
            sys.stderr.write(f"Error: {str(e)}\n")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

def main():
    _main(sys.argv[1:])

if __name__ == "__main__":
    main()
