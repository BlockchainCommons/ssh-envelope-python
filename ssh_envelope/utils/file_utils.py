import logging
from . import logconfig

def read_file(path):
    try:
        with open(path, 'rb') as key_file:
            data = key_file.read()
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found at path: {path}")
    except PermissionError:
        raise PermissionError(f"Permission denied while reading file: {path}")
