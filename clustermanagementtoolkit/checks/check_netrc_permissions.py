# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Check permissions for .netrc; this should probably use the generic path checker.
"""

import errno
from pathlib import Path
import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtpaths import NETRC_PATH

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def check_netrc_permissions(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether the .netrc are sufficiently strict (0600 is required to satisfy Ansible).

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
                verbose (bool): True for verbose output about actions
                exit_on_error (bool): Exit if there an error?
                quiet_on_ok (bool): Only output messages when issues are found?
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
    exit_on_error = deep_get(kwargs, DictPath("exit_on_error"), False)
    quiet_on_ok = deep_get(kwargs, DictPath("quiet_on_ok"), False)

    abort = False

    if verbose:
        ansithemeprint([ANSIThemeStr("[Checking whether permissions for ", "phase"),
                        ANSIThemeStr(".netrc", "path"),
                        ANSIThemeStr(" are sufficiently strict on ", "phase"),
                        ANSIThemeStr("localhost", "hostname"),
                        ANSIThemeStr("]", "phase")])

    path_entry = Path(NETRC_PATH)
    if not path_entry.exists():
        if verbose:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Note", "critical"),
                            ANSIThemeStr(":", "default")])
            ansithemeprint([ANSIThemeStr(f"    {NETRC_PATH}", "path"),
                            ANSIThemeStr(" does not exist.\n", "default")])
        note += 1
        return abort, critical, error, warning, note

    path_stat = path_entry.stat()
    path_permissions = path_stat.st_mode & 0o777

    if path_permissions not in (0o600, 0o400):
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Critical", "critical"),
                        ANSIThemeStr(":", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    The permissions for ", "default"),
                        ANSIThemeStr(f"{NETRC_PATH}", "path"),
                        ANSIThemeStr(" are ", "default"),
                        ANSIThemeStr(f"{path_permissions:03o}", "emphasis"),
                        ANSIThemeStr(";", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    the required permissions are ", "default"),
                        ANSIThemeStr(f"{0o600:03o}", "emphasis"),
                        ANSIThemeStr(" (or stricter).", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("  ", "default"),
                        ANSIThemeStr("Justification", "emphasis"),
                        ANSIThemeStr(": ", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("    Ansible will refuse to fetch files if "
                                     "the permissions for ", "default"),
                        ANSIThemeStr(f"{NETRC_PATH}", "path"),
                        ANSIThemeStr(" are not sufficiently strict\n", "default")], stderr=True)
        if exit_on_error:
            sys.exit(errno.EPERM)
        critical += 1
    elif not quiet_on_ok:
        ansithemeprint([ANSIThemeStr("  OK\n", "emphasis")])

    return abort, critical, error, warning, note
