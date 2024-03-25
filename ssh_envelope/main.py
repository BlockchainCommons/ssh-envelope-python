import logging
import argparse
import sys

from ssh_envelope import logconfig
__all__ = ['logconfig']

from ssh_envelope.envelope_utils import export_ssh_object
from ssh_envelope.ssh_object_utils import derive_public_key, generate_ed25519_private, import_ssh_object

logger = logging.getLogger(__name__)

def import_command(args: argparse.Namespace):
    logger.info(f"Importing SSH object")
    object_data = None

    if args.object:
        logger.info("Reading SSH object from --object")
        object_data = args.object
    elif args.file:
        logger.info("Reading SSH object from --file")
        with open(args.file, 'r') as file:
            object_data = file.read()
    else:
        logger.info("Reading SSH object from stdin")
        object_data = sys.stdin.read()

    envelope = import_ssh_object(object_data)
    if envelope is None:
        raise ValueError("Failed to import SSH object")

    sys.stdout.write(envelope + '\n')

def export_command(args: argparse.Namespace):
    logger.info(f"Exporting object")
    envelope = None

    if args.envelope:
        logger.info("Reading envelope from --envelope")
        envelope = args.envelope
    elif args.file:
        logger.info("Reading envelope from --file")
        with open(args.file, 'r') as file:
            envelope = file.read()
    else:
        logger.info("Reading envelope from stdin")
        envelope = sys.stdin.read()

    object = export_ssh_object(envelope)
    if object is None:
        raise ValueError("Failed to export SSH object")

    sys.stdout.write(object + '\n')

def generate_command(args: argparse.Namespace):
    logger.info(f"Generating Ed25519 private key")
    envelope = generate_ed25519_private()
    sys.stdout.write(envelope + '\n')

def public_command(args: argparse.Namespace):
    logger.info(f"Deriving public key from private key")

    envelope = None
    if args.envelope:
        logger.info("Reading envelope from --envelope")
        envelope = args.envelope
    elif args.file:
        logger.info("Reading envelope from --file")
        with open(args.file, 'r') as file:
            envelope = file.read()
    else:
        logger.info("Reading envelope from stdin")
        envelope = sys.stdin.read()

    public_key_envelope = derive_public_key(envelope)
    sys.stdout.write(public_key_envelope + '\n')

def main():
    parser = argparse.ArgumentParser(description="Envelope/SSH Key Management Tool")
    subparsers = parser.add_subparsers(help='commands')

    # import_command
    parser_import = subparsers.add_parser('import', help='Convert an SSH object to an envelope')
    parser_import.add_argument('--object', help='SSH object as a string', default=None)
    parser_import.add_argument('--file', help='Path to the file containing the SSH object', default=None)
    parser_import.set_defaults(func=import_command)

    # export_command
    parser_export = subparsers.add_parser('export', help='Convert an envelope to an SSH object')
    parser_export.add_argument('--envelope', help='Envelope to export', default=None)
    parser_export.add_argument('--file', help='Path to the file containing the envelope', default=None)
    parser_export.set_defaults(func=export_command)

    # generate_command
    parser_generate = subparsers.add_parser('generate', help='Generate a new Ed25519 private key')
    parser_generate.set_defaults(func=generate_command)

    # public_command
    parser_public = subparsers.add_parser('public', help='Derive a public key from a private key')
    parser_public.add_argument('--envelope', help='Private key envelope', default=None)
    parser_public.add_argument('--file', help='Path to the file containing the private key envelope', default=None)
    parser_public.set_defaults(func=public_command)

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
