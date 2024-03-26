import logging
import argparse
import sys

from ssh_envelope import logconfig
__all__ = ['logconfig']

from ssh_envelope.envelope import Envelope
from ssh_envelope.ssh_keygen_utils import sign_message

from ssh_envelope.envelope_utils import export_ssh_object
from ssh_envelope.ssh_object_utils import derive_public_key, generate_ed25519_private, import_ssh_object

logger = logging.getLogger(__name__)

def import_command(args: argparse.Namespace):
    logger.info(f"Importing SSH object")
    object_data = None

    if args.object:
        logger.info("Reading SSH object from --object")
        object_data = args.object
    elif args.object_path:
        logger.info("Reading SSH object from --object-path")
        with open(args.object_path, 'r') as file:
            object_data = file.read()
    else:
        logger.info("Reading SSH object from stdin")
        object_data = sys.stdin.read()

    envelope = import_ssh_object(object_data)

    sys.stdout.write(envelope.ur + '\n')

def export_command(args: argparse.Namespace):
    logger.info(f"Exporting object")
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

    object = export_ssh_object(envelope)
    if object is None:
        raise ValueError("Failed to export SSH object")

    sys.stdout.write(f"{object}" + '\n')

def generate_command(args: argparse.Namespace):
    logger.info(f"Generating Ed25519 private key")
    envelope = generate_ed25519_private()
    sys.stdout.write(envelope.ur + '\n')

def public_command(args: argparse.Namespace):
    logger.info(f"Deriving public key from private key")

    key: Envelope | None = None
    if args.key:
        logger.info("Reading key from --key")
        key = Envelope(args.key)
    elif args.key_path:
        logger.info("Reading key from --key-path")
        with open(args.key_path, 'r') as file:
            key = Envelope(file.read())
    else:
        logger.info("Reading key from stdin")
        key = Envelope(sys.stdin.read())

    public_key_envelope = derive_public_key(key)
    sys.stdout.write(public_key_envelope.ur + '\n')

def sign_data_command(args: argparse.Namespace):
    logger.info(f"Signing data")

    if not args.key and not args.key_path and not args.message and not args.message_path:
        raise ValueError("At least one of the key envelope (--key or --key-path) or the message to be signed (--message or --message-path) must be provided on the command line: they cannot both be provided via stdin.")

    key: Envelope | None = None
    if args.key:
        logger.info("Reading key from --key")
        key = args.key
    elif args.key_path:
        logger.info("Reading key from --key-path")
        with open(args.key_path, 'r') as file:
            key = Envelope(file.read())
    elif not args.message and not args.message_path:
        logger.info("Reading key from stdin")
        key = Envelope(sys.stdin.read())

    message = None
    if args.message:
        logger.info("Reading message from --message")
        message = args.message.encode()
    elif args.message_path:
        logger.info("Reading message from --message-path")
        with open(args.message_path, 'rb') as file:
            message = file.read()
    elif not key:
        logger.info("Reading message from stdin")
        message = sys.stdin.buffer.read()

    if not key:
        raise ValueError("Key envelope not provided.")
    if not message:
        raise ValueError("Message to sign not provided.")

    signature_envelope = sign_message(message, key, args.namespace)
    sys.stdout.write(signature_envelope.ur + '\n')

def main():
    parser = argparse.ArgumentParser(description="Envelope/SSH Key Management Tool")
    subparsers = parser.add_subparsers(help='commands')

    # import_command
    parser_import = subparsers.add_parser('import', help='Convert an SSH object to an envelope')
    parser_import.add_argument('-o', '--object', help='SSH object as a string', default=None)
    parser_import.add_argument('-O', '--object-path', help='Path to the file containing the SSH object', default=None)
    parser_import.set_defaults(func=import_command)

    # export_command
    parser_export = subparsers.add_parser('export', help='Convert an envelope to an SSH object')
    parser_export.add_argument('-e', '--envelope', help='Envelope to export', default=None)
    parser_export.add_argument('-E', '--envelope-path', help='Path to the file containing the envelope', default=None)
    parser_export.set_defaults(func=export_command)

    # generate_command
    parser_generate = subparsers.add_parser('generate', help='Generate a new Ed25519 private key')
    parser_generate.set_defaults(func=generate_command)

    # public_command
    parser_public = subparsers.add_parser('public', help='Derive a public key from a private key')
    parser_public.add_argument('-k', '--key', help='Private key envelope', default=None)
    parser_public.add_argument('-K', '--key-path', help='Path to the file containing the private key envelope', default=None)
    parser_public.set_defaults(func=public_command)

    # sign_data_command
    parser_sign = subparsers.add_parser('sign-data', help='Sign data with a private key')
    parser_sign.add_argument('-k', '--key', help='Private key envelope', default=None)
    parser_sign.add_argument('-K', '--key-path', help='Path to the file containing the private key envelope', default=None)
    parser_sign.add_argument('-m', '--message', help='Message to sign', default=None)
    parser_sign.add_argument('-M', '--message-path', help='Path to the file containing the message to sign', default=None)
    parser_sign.add_argument('-n', '--namespace', help='Namespace for the signature', default='file')
    parser_sign.set_defaults(func=sign_data_command)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        try:
            args.func(args)
        except Exception as e:
            sys.stderr.write(f"Error: {str(e)}\n")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
