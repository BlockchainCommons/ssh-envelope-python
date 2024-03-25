import os
import subprocess

def run_command(command: list[str], stdin: bytes | None = None) -> bytes:
    """
    Run a command in the shell and return the output.

    Args:
        command (list[str]): The command to be executed as a list of strings.
        stdin (bytes | None): Optional bytes to send to the command's standard input.

    Returns:
        str: The output of the command.
    """
    env = os.environ.copy()
    cargo_bin_path = os.path.expanduser("~/.cargo/bin")
    env["PATH"] = cargo_bin_path + os.pathsep + env["PATH"]

    input_data = stdin if stdin else None
    result = subprocess.run(command, input=input_data, capture_output=True, env=env)

    error_status = result.returncode
    stdout = result.stdout
    stderr = result.stderr

    if error_status != 0:
        raise Exception(f"Command '{command}' failed with error code {error_status}: {stderr}")

    return stdout
