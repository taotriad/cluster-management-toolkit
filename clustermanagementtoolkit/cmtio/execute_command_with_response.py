# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import subprocess  # nosec
from subprocess import PIPE, STDOUT  # nosec


# This executes a command with the output captured
def execute_command_with_response(args: list[str], env: dict | None = None,
                                  stdinput: bytes | None = None) -> tuple[str, int]:
    """
    Executes a command and returns stdout.

        Parameters:
            args ([str]): The commandline
            env (dict): Environment variables to set [optional]
            stdinput ([str]): stdin to pass through the process [optional]
        Returns:
            (str, int):
                (str): The stdout from the execution
                (int): The return value from the execution
        Exceptions:
            OSError ("[Errno 26] Text file busy"): The file is being written to by another process
    """
    if env is None:
        result = subprocess.run(args, stdout=PIPE, stderr=STDOUT,
                                input=stdinput, check=False)
    else:
        result = subprocess.run(args, stdout=PIPE, stderr=STDOUT,
                                input=stdinput, env=env, check=False)
    retval = result.returncode

    return result.stdout.decode("utf-8", errors="replace"), retval
