# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Check whether the user has sudo permissions and can sudo without a password.
"""

import re
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtio import execute_command_with_response

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals
def check_sudo_configuration(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether the user is in /etc/sudoers or /etc/sudoers.d,
    and whether the user can sudo without a password.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                user (str): Username of the executing user
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
                verbose (bool): True for verbose output about actions
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
    quiet_on_ok: bool = deep_get(kwargs, DictPath("quiet_on_ok"), False)

    abort = False

    if not user:
        raise ProgrammingError(f"{__name__}() called without user")

    if verbose:
        ansithemeprint([ANSIThemeStr("[Checking whether ", "phase"),
                        ANSIThemeStr(f"{user}", "path"),
                        ANSIThemeStr(" is in ", "phase"),
                        ANSIThemeStr("/etc/sudoers", "path"),
                        ANSIThemeStr(" or ", "phase"),
                        ANSIThemeStr("/etc/sudoers.d", "path"),
                        ANSIThemeStr(" on ", "phase"),
                        ANSIThemeStr("localhost", "hostname"),
                        ANSIThemeStr("]", "phase")])
    args = ["/usr/bin/sudo", "-l"]
    result, _retval = execute_command_with_response(args)

    sudoer = True

    sudo_msg_regex = re.compile(r"^User ([^\s]+) is not allowed to run sudo on.*")

    for line in result.splitlines():
        tmp = sudo_msg_regex.match(line)
        if tmp is not None:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    The user ", "default"),
                            ANSIThemeStr(user, "path"),
                            ANSIThemeStr(" is not in ", "default"),
                            ANSIThemeStr("/etc/sudoers", "path"),
                            ANSIThemeStr(" or ", "default"),
                            ANSIThemeStr("/etc/sudoers.d", "path"),
                            ANSIThemeStr(".\n", "default")], stderr=True)
            error += 1
            sudoer = False
            break

    if sudoer:
        if not quiet_on_ok:
            ansithemeprint([ANSIThemeStr("  OK\n", "ok")])

        if verbose:
            ansithemeprint([ANSIThemeStr("[Checking whether", "phase"),
                            ANSIThemeStr(f" {user} ", "path"),
                            ANSIThemeStr("can perform passwordless sudo", "phase"),
                            ANSIThemeStr(" on ", "phase"),
                            ANSIThemeStr("localhost", "hostname"),
                            ANSIThemeStr("]", "phase")])
        passwordless_sudo = False

        sudo_permissions_regex = re.compile(r"^\s*\(ALL(\s*:\s*ALL)?\)\s*NOPASSWD:\s*ALL\s*$")

        for line in result.splitlines():
            tmp = sudo_permissions_regex.match(line)
            if tmp is not None:
                if not quiet_on_ok:
                    ansithemeprint([ANSIThemeStr("  OK\n", "emphasis")])
                passwordless_sudo = True
                break

        if not passwordless_sudo:
            ansithemeprint([ANSIThemeStr("  ", "default"),
                            ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(":", "default")], stderr=True)
            ansithemeprint([ANSIThemeStr("    The user ", "default"),
                            ANSIThemeStr(user, "path"),
                            ANSIThemeStr(" cannot perform passwordless sudo.\n",
                                         "default")], stderr=True)
            error += 1

    return abort, critical, error, warning, note
