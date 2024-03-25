import os
import secrets

def read_file(path: str) -> bytes:
    try:
        with open(path, 'rb') as key_file:
            data = key_file.read()
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found at path: {path}")
    except PermissionError:
        raise PermissionError(f"Permission denied while reading file: {path}")

def secure_delete(file_path: str | None, passes: int = 3) -> None:
    if not file_path or not os.path.exists(file_path):
        return

    with open(file_path, "ba+") as file:
        length = file.tell()

        for _ in range(passes):
            file.seek(0)
            file.write(secrets.token_bytes(length))

    os.remove(file_path)
