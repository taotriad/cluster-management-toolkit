# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Identify what hardware architecture is in use.
"""

import errno
import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmtio import execute_command_with_response
from clustermanagementtoolkit.cmtio import secure_which

from clustermanagementtoolkit.cmtlib.identify_distro import identify_distro

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityPolicy
from clustermanagementtoolkit.cmttypes import deep_get


def identify_arch(**kwargs: Any) -> str:
    """
    Identify what hardware architecture is in use.
    The architecture name we need is the one used when fetching
    distro packages; this means that the same architecture
    maybe be identified differently depending on what distribution
    is in use.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            (str): The identified hardware architecture; empty if no supported
                   architecture could be identified.
    """
    exit_on_failure: bool = deep_get(kwargs, DictPath("exit_on_failure"), True)
    error_on_failure: bool = deep_get(kwargs, DictPath("error_on_failure"), True)
    os_distro = identify_distro()
    arch: str = ""

    # Find out what architecture this is run on
    match os_distro:
        case "debian":
            cmd = "dpkg-architecture"
            extra_args = ["-q", "DEB_HOST_ARCH"]
        case "fedora" | "rhel":
            # While this is the same as the catch-all case,
            # it has a separate entry to indicate that we know that this
            # is the correct arch to use here, while the default
            # case is just a best guess.
            cmd = "arch"
            extra_args = []
        case _:
            cmd = "arch"
            extra_args = []

    try:
        cmd_path = secure_which(FilePath(cmd),
                                fallback_allowlist=["/bin", "/usr/bin"],
                                security_policy=SecurityPolicy.ALLOWLIST_STRICT)
    except FileNotFoundError:  # pragma: no cover
        if error_on_failure:
            ansithemeprint([ANSIThemeStr("Error:", "error"),
                            ANSIThemeStr(" The command “", "default"),
                            ANSIThemeStr(f"{cmd}", "command"),
                            ANSIThemeStr("“ seems to be missing; aborting.",
                                         "default")], stderr=True)
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.ENOENT)

        return ""

    args = [cmd_path] + extra_args
    response, _retval = execute_command_with_response(args)
    splitlines = response.splitlines()

    if cmd in ("dpkg-architecture", "arch"):
        arch = splitlines[0]

    return arch
