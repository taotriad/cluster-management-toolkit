# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import re
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtio import execute_command_with_response

from clustermanagementtoolkit.cmtpaths import SSH_BIN_PATH

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def check_known_hosts_hashing(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether ssh known_hosts hashing is enabled.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
                verbose (bool): True for verbose output about actions
        Returns:
            (bool, int, int, int, int):
                (bool): Is this error severe enough that we should abort immediately?
                (int): The new count of critical severity security issues
                (int): The new count of error severity security issues
                (int): The new count of warning severity security issues
                (int): The new count of note severity security issues
    """
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)
    verbose = deep_get(kwargs, DictPath("verbose"), True)

    abort = False

    if verbose:
        ansithemeprint([ANSIThemeStr("[Checking whether hashing of ", "phase"),
                        ANSIThemeStr(".ssh/known_hosts", "path"),
                        ANSIThemeStr(" is enabled on ", "phase"),
                        ANSIThemeStr("localhost", "hostname"),
                        ANSIThemeStr("]", "phase")])
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Note", "note"),
                        ANSIThemeStr(":", "default")])
        ansithemeprint([ANSIThemeStr("    Since ", "default"),
                        ANSIThemeStr("ssh", "programname"),
                        ANSIThemeStr(" settings can vary per host this test "
                                     "is not 100% reliable.\n", "default")])
    args = [SSH_BIN_PATH, "-G", "localhost"]
    result, _retval = execute_command_with_response(args)

    hashknownhosts_regex = re.compile(r"^hashknownhosts\s+yes$")

    for line in result.splitlines():
        tmp = hashknownhosts_regex.match(line)
        if tmp is not None:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Warning", "warning"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    Hashing of ", "default"),
                            ANSIThemeStr(".ssh/known_hosts", "path"),
                            ANSIThemeStr(" is enabled;", "default"),
                            ANSIThemeStr(" this may cause issues with ", "default"),
                            ANSIThemeStr("paramiko", "programname"),
                            ANSIThemeStr(".\n", "default")], stderr=True)
            warning += 1
            break

    return abort, critical, error, warning, note
