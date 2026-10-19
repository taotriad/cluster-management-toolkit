# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import subprocess  # nosec

from clustermanagementtoolkit.cmttypes import FilePath


# This executes a command without capturing the output
def execute_command(args: list[FilePath | str],
                    env: dict | None = None, comparison: int = 0) -> bool:
    """
    Executes a command.

        Parameters:
            args ([str]): The commandline
            env (dict): Environment variables to set
            comparison (int): The value to compare retval to
        Returns:
            (bool): True if retval.returncode == comparison, False otherwise
    """
    if env is None:
        result = subprocess.run(args, check=False)
    else:
        result = subprocess.run(args, env=env, check=False)
    return result.returncode == comparison
