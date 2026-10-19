# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import os
from functools import partial
from typing import Any

from clustermanagementtoolkit.cmtio.check_path import check_path
from clustermanagementtoolkit.cmtio.join_securitystatus_set import join_securitystatus_set

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError


# pylint: disable-next=too-many-branches
def secure_write_string(path: FilePath, string: str | bytes, **kwargs: Any) -> None:
    """
    Write a string to a file in a safe manner.

        Parameters:
            path (FilePath): The path to write to
            string (str | bytes): The string to write
            **kwargs (dict[str, Any]): Keyword arguments
                permissions (int): File permissions (None uses system defaults)
                write_mode (str): [w, a, x, wb, ab, xb] Write, Append, Exclusive Write,
                                                        text or binary
                allow_relative_path (bool): Is it acceptable to have the path not resolve to self?
                temporary (bool): Is the file a tempfile?
                                  If so we need to disable the check for parent permissions
        Raises:
            cmttypes.FilePathAuditError
    """
    permissions: int | None = deep_get(kwargs, DictPath("permissions"), None)
    write_mode: str = deep_get(kwargs, DictPath("write_mode"), "w")
    allow_relative_path: bool = deep_get(kwargs, DictPath("allow_relative_path"), False)
    temporary: bool = deep_get(kwargs, DictPath("temporary"), False)

    if write_mode not in ("a", "ab", "w", "wb", "x", "xb"):
        raise ValueError(f"Invalid write mode “{write_mode}“; "
                         "permitted modes: “a(b)“ (append (binary)), "
                         "“w(b)“ (write (binary)) and “x(b)“ (exclusive write (binary))")

    checks: list[SecurityChecks] = [
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.IS_FILE,
    ]

    if temporary:
        checks.remove(SecurityChecks.PARENT_PERMISSIONS)

    if not allow_relative_path:
        checks += [
            SecurityChecks.PARENT_RESOLVES_TO_SELF,
            SecurityChecks.RESOLVES_TO_SELF,
        ]

    violations = check_path(path, checks=checks)

    if violations != [SecurityStatus.OK]:
        violations_joined = join_securitystatus_set(",", set(violations))
        raise FilePathAuditError(f"Violated rules: {violations_joined}", path=path)

    if "b" in write_mode:
        # We have no default recourse if this write fails, so if the caller
        # can handle the failure they have to capture the exception.
        try:
            if permissions is None:
                with open(path, write_mode) as f:
                    f.write(string)
            else:
                with open(path, write_mode, opener=partial(os.open, mode=permissions)) as f:
                    f.write(string)
        except FileExistsError as e:
            if write_mode == "xb":
                raise FilePathAuditError(f"Violated rules: {SecurityStatus.EXISTS!r}",
                                         path=path) from e
    else:
        # We have no default recourse if this write fails, so if the caller
        # can handle the failure they have to capture the exception.
        try:
            if permissions is None:
                with open(path, write_mode, encoding="utf-8") as f:
                    f.write(string)
            else:
                with open(path, write_mode, opener=partial(os.open, mode=permissions),
                          encoding="utf-8") as f:
                    f.write(string)
        except FileExistsError as e:
            if write_mode == "x":
                raise FilePathAuditError(f"Violated rules: {SecurityStatus.EXISTS!r}",
                                         path=path) from e
