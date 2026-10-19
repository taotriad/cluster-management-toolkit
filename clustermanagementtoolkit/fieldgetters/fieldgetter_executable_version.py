# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A fieldgetter that provides the version of an executable.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmtio import execute_command_with_response, secure_which

from clustermanagementtoolkit.cmtpaths import HOMEDIR

from clustermanagementtoolkit.cmttypes import DictPath, FilePath, SecurityPolicy
from clustermanagementtoolkit.cmttypes import deep_get


def fieldgetter_executable_version(**kwargs: Any) -> list[str]:
    """
    A fieldgetter that provides the version from an executable.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                executable (str): The executable to get the version for
                args ([str]): The arguments to pass to the executable
                version_regex (str): The regular expression to use to extract the version
        Returns:
            [str]: The version tuple
    """
    executables: FilePath | list[FilePath] = deep_get(kwargs, DictPath("executable"), "")
    args: list[str] = deep_get(kwargs, DictPath("args"), [])
    version_regex: str = deep_get(kwargs, DictPath("version_regex"), '')

    security_policy = SecurityPolicy.ALLOWLIST_RELAXED
    fallback_allowlist = ["/bin", "/sbin", "/usr/bin", "/usr/sbin",
                          "/usr/local/bin", "/usr/local/sbin", f"{HOMEDIR}/bin"]

    if isinstance(executables, (str, FilePath)):
        executables = [FilePath(executables)]

    version: list[str] = []

    for executable in executables:
        try:
            executable_path = secure_which(FilePath(executable),
                                           fallback_allowlist=fallback_allowlist,
                                           security_policy=security_policy)
        except FileNotFoundError:
            continue

        try:
            result, _retval = execute_command_with_response([executable_path] + args)
        except OSError as e:  # pragma: nocover
            if str(e).startswith("[Errno 26] Text file busy"):
                continue

        if result:
            for line in result.splitlines():
                if (tmp := re.match(version_regex, line)) is not None:
                    version += list(tmp.groups())
                    break
        if version:
            break

    return ["".join(version)]
