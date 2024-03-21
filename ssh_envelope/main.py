import logging
import argparse
import sys

from .utils import logconfig
__all__ = ['logconfig']

from .utils.ssh_object_utils import import_ssh_object

logger = logging.getLogger(__name__)

def import_object(args):
    logger.info(f"Importing object")
    data = args.data

    if data is None:
        logger.info("Reading data from stdin")
        data = sys.stdin.read()

    envelope = import_ssh_object(data)
    if envelope is None:
        raise ValueError("Failed to import SSH object")

    sys.stdout.write(envelope)

def export_object(args):
    logger.info(f"Exporting object")
    # Implement the export_object functionality here

def main():
    parser = argparse.ArgumentParser(description="Envelope/SSH Key Management Tool")
    subparsers = parser.add_subparsers(help='commands')

    # import_object command
    parser_import_public = subparsers.add_parser('import', help='Convert an SSH object to an envelope')
    parser_import_public.add_argument('data', nargs='?', default=None, help='Object to import')
    parser_import_public.set_defaults(func=import_object)

    # export_object command
    parser_export_public = subparsers.add_parser('export', help='Convert an envelope to an SSH object')
    parser_export_public.add_argument('envelope', help='Envelope to export')
    parser_export_public.set_defaults(func=export_object)

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
