# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import errno
from pathlib import Path
import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtpaths import DOT_ANSIBLE_PATH

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


def check_ansible_dir_permissions(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether .ansible is owned and accessible by the user.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                user (str): Username of the executing user
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
    user: str = deep_get(kwargs, DictPath("user"), "")
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)
    verbose: bool = deep_get(kwargs, DictPath("verbose"), True)
    exit_on_error: bool = deep_get(kwargs, DictPath("exit_on_error"), False)
    quiet_on_ok: bool = deep_get(kwargs, DictPath("quiet_on_ok"), False)

    abort = False

    if not user:
        raise ProgrammingError(f"{__name__}() called without user")

    if verbose:
        ansithemeprint([ANSIThemeStr("[Checking whether ownership for ", "phase"),
                        ANSIThemeStr(".ansible", "path"),
                        ANSIThemeStr(" is correct on ", "phase"),
                        ANSIThemeStr("localhost", "hostname"),
                        ANSIThemeStr("]", "phase")])

    path_entry = Path(DOT_ANSIBLE_PATH)
    # It's OK if .ansible doesn't exist; it will be created on execution
    if path_entry.exists():
        path_stat = path_entry.stat()
        path_permissions = path_stat.st_mode

        if path_permissions & 0o300 != 0o300:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Critical", "critical"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    The permissions for ", "default"),
                            ANSIThemeStr(f"{DOT_ANSIBLE_PATH}", "path"),
                            ANSIThemeStr(" are ", "default"),
                            ANSIThemeStr(f"{path_permissions:03o}", "emphasis"),
                            ANSIThemeStr(";", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    Ansible will not be able to ", "default"),
                            ANSIThemeStr("run properly.", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Justification", "emphasis"),
                            ANSIThemeStr(": ", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    Ansible will fail to run if it cannot write to ",
                                         "default"),
                            ANSIThemeStr(f"{DOT_ANSIBLE_PATH}", "path"),
                            ANSIThemeStr("\n", "default")], stderr=True)
            if exit_on_error:
                sys.exit(errno.EPERM)
            critical += 1
        if path_entry.owner() != user:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Critical", "critical"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    The executing user ", "default"),
                            ANSIThemeStr(f"{user}", "path"),
                            ANSIThemeStr(" is not the owner of ", "default"),
                            ANSIThemeStr(f"{DOT_ANSIBLE_PATH}", "path")], stderr=True)
            ansithemeprint([ANSIThemeStr("    Ansible will not be able to ", "default"),
                            ANSIThemeStr("run properly.", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Justification", "emphasis"),
                            ANSIThemeStr(": ", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    Ansible will fail to run if it cannot write to ",
                                         "default"),
                            ANSIThemeStr(f"{DOT_ANSIBLE_PATH}", "path"),
                            ANSIThemeStr("\n", "default")], stderr=True)
            if exit_on_error:
                sys.exit(errno.EPERM)
            critical += 1
        elif not quiet_on_ok:
            ansithemeprint([ANSIThemeStr("  OK\n", "emphasis")])
    elif not quiet_on_ok:
        ansithemeprint([ANSIThemeStr("  OK\n", "emphasis")])

    return abort, critical, error, warning, note
