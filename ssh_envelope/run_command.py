import os
import subprocess

def run_command(command: list[str]) -> str:
    """
    Run a command in the shell and return the output.

    Args:
        command (str): The command to be executed.

    Returns:
        str: The output of the command.
    """
    env = os.environ.copy()
    cargo_bin_path = os.path.expanduser("~/.cargo/bin")
    env["PATH"] = cargo_bin_path + os.pathsep + env["PATH"]
    # print(command)
    result = subprocess.run(command, capture_output=True, text=True, env=env)
    error_status = result.returncode
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if error_status != 0:
        raise Exception(f"Command '{command}' failed with error code {error_status}: {stderr}")
    return stdout
