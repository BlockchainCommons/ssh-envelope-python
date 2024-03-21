import logging
from . import logconfig

import os
import cbor2
import subprocess

ssh_private_key_tag = 40800
ssh_public_key_tag = 40801
ssh_signature_tag = 40802
ssh_certificate_tag = 40803

def run_command(command):
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

def tagged_string_hex(string, tag):
    return cbor2.dumps(cbor2.CBORTag(tag, string)).hex()

def string_envelope(string):
    return run_command(["envelope", "subject", "type", "string", string])

def wrap_envelope(envelope):
    return run_command(["envelope", "subject", "type", "wrapped", envelope])

def tagged_string_envelope(string, tag):
    hex = tagged_string_hex(string, tag)
    return run_command(["envelope", "subject", "type", "cbor", hex])

def known_value_envelope(value):
    return run_command(["envelope", "subject", "type", "known", value])

def assertion_envelope(pred_type, pred_value, obj_type, obj_value):
    return run_command(["envelope", "subject", "assertion", pred_type, pred_value, obj_type, obj_value])

def verified_by_assertion_envelope(signature):
    return assertion_envelope("known", "verifiedBy", "cbor", signature)

def format_envelope(envelope):
    return run_command(["envelope", "format", envelope])

def ssh_private_key_envelope(private_key):
    return tagged_string_envelope(private_key, ssh_private_key_tag)

def ssh_public_key_envelope(public_key):
    return tagged_string_envelope(public_key, ssh_public_key_tag)

def ssh_signature_envelope(signature):
    return tagged_string_envelope(signature, ssh_signature_tag)

# signature = tagged_string_hex("my_signature", ssh_signature_tag)
# assertion = verified_by_assertion_envelope(signature)
# print(format_envelope(assertion))

private_key = ssh_private_key_envelope("my_private_key")
# private_key_envelope = ssh_private_key_envelope(private_key)
print(format_envelope(private_key))
