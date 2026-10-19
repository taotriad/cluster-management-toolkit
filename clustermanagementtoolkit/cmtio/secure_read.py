# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from pathlib import PurePath

from clustermanagementtoolkit.cmtio.check_path import check_path
from clustermanagementtoolkit.cmtio.join_securitystatus_set import join_securitystatus_set

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError


def secure_read(path: FilePath,
                checks: list[SecurityChecks] | None = None,
                directory_is_symlink: bool = False,
                read_mode: str = "r", temporary: bool = False) -> str | bytes:
    """
    Read the content of a file in a safe manner.

        Parameters:
            path (FilePath): The path to read from
            checks ([SecurityChecks]): A list of checks that should be performed
            directory_is_symlink (bool): The directory that the path points to is a symlink
            read_mode (str): [r, rb] Read text or binary
            temporary (bool): Is the file a tempfile?
                              If so we need to disable the check for parent permissions
        Returns:
            (str | bytes): The read string
        Raises:
            cmttypes.FilePathAuditError
    """
    if read_mode not in ("r", "rb"):
        raise ValueError(f"Invalid read mode “{read_mode}“; "
                         "permitted modes: “r(b)“ (read (binary))")

    if checks is None:
        if directory_is_symlink:
            parent_dir = FilePath(PurePath(path).parent)

            # The directory itself may be a symlink. This is expected behaviour when installing
            # from a git repo, but we only allow it if the rest of the path components are secure.
            checks = [
                SecurityChecks.PARENT_RESOLVES_TO_SELF,
                SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
                SecurityChecks.OWNER_IN_ALLOWLIST,
                SecurityChecks.PARENT_PERMISSIONS,
                SecurityChecks.PERMISSIONS,
                SecurityChecks.EXISTS,
                SecurityChecks.IS_DIR,
            ]

            if temporary:
                checks.remove(SecurityChecks.PARENT_PERMISSIONS)

            violations = check_path(parent_dir, checks=checks)
            if violations != [SecurityStatus.OK]:
                violations_joined = join_securitystatus_set(",", set(violations))
                raise FilePathAuditError(f"Violated rules: {violations_joined}", path=parent_dir)

            # We do not want to check that parent resolves to itself,
            # because when we have an installation with links directly to the git repo
            # the parsers directory will be a symlink.
            checks = [
                SecurityChecks.RESOLVES_TO_SELF,
                SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
                SecurityChecks.OWNER_IN_ALLOWLIST,
                SecurityChecks.PARENT_PERMISSIONS,
                SecurityChecks.PERMISSIONS,
                SecurityChecks.EXISTS,
                SecurityChecks.IS_FILE,
            ]
        else:
            checks = [
                SecurityChecks.PARENT_RESOLVES_TO_SELF,
                SecurityChecks.RESOLVES_TO_SELF,
                SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
                SecurityChecks.OWNER_IN_ALLOWLIST,
                SecurityChecks.PARENT_PERMISSIONS,
                SecurityChecks.PERMISSIONS,
                SecurityChecks.EXISTS,
                SecurityChecks.IS_FILE,
            ]

    if temporary:
        try:
            checks.remove(SecurityChecks.PARENT_PERMISSIONS)
        except ValueError:
            pass

    violations = check_path(path, checks=checks)

    if violations != [SecurityStatus.OK]:
        violations_joined = join_securitystatus_set(",", set(violations))
        raise FilePathAuditError(f"Violated rules: {violations_joined}", path=path)

    # We have no default recourse if this read fails, so if the caller
    # can handle the failure they have to capture the exception.
    if read_mode == "r":
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            string: str | bytes = f.read()
    else:
        with open(path, "rb") as bf:
            string = bf.read()

    return string
