#!python3

import logging
from .utils import logconfig
import argparse

import sys
from .utils.file_utils import read_file
from .utils.ssh_keys_utils import deserialize_ssh_private_key, serialize_private_key

logger = logging.getLogger(__name__)

def import_object(args):
    logger.info(f"Importing object")
    data = args.data

    if data is None:
        logger.info("Reading data from stdin")
        data = sys.stdin.read()

    print(data)
    pem = deserialize_ssh_private_key(data.encode())
    pem_key = serialize_private_key(pem)
    print(pem_key)

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
        args.func(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
