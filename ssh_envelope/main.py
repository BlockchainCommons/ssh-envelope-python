import logging
import argparse
import sys

from ssh_envelope import logconfig
__all__ = ['logconfig']

from ssh_envelope.ssh_object_utils import import_ssh_object

logger = logging.getLogger(__name__)

def import_object(args):
    logger.info(f"Importing object")
    object_data = None

    if args.object:
        logger.info("Reading data from --object")
        object_data = args.object
    elif args.file:
        logger.info("Reading data from --file")
        with open(args.file, 'r') as file:
            object_data = file.read()
    else:
        logger.info("Reading data from stdin")
        object_data = sys.stdin.read()

    envelope = import_ssh_object(object_data)
    if envelope is None:
        raise ValueError("Failed to import SSH object")

    sys.stdout.write(envelope + '\n')

def export_object(args):
    logger.info(f"Exporting object")
    # Implement the export_object functionality here

def main():
    parser = argparse.ArgumentParser(description="Envelope/SSH Key Management Tool")
    subparsers = parser.add_subparsers(help='commands')

    # import_object command
    parser_import = subparsers.add_parser('import', help='Convert an SSH object to an envelope')
    parser_import.add_argument('--object', help='SSH object as a string', default=None)
    parser_import.add_argument('--file', help='Path to the file containing the SSH object', default=None)
    parser_import.set_defaults(func=import_object)

    # export_object command
    parser_export = subparsers.add_parser('export', help='Convert an envelope to an SSH object')
    parser_export.add_argument('envelope', help='Envelope to export')
    parser_export.set_defaults(func=export_object)

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
