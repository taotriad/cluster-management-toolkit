# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from pathlib import Path

from clustermanagementtoolkit.cmtio.check_path import check_path
from clustermanagementtoolkit.cmtio.join_securitystatus_set import join_securitystatus_set

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError

from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus


def secure_rm(path: FilePath, ignore_non_existing: bool = False) -> None:
    """
    Remove a file.

        Parameters:
            path (FilePath): The path to the file to remove
        Raises:
            cmttypes.FilePathAuditError
            FileNotFoundError
    """
    checks: list[SecurityChecks] = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_FILE,
    ]

    violations = check_path(path, checks=checks)

    ignoring_non_existing = False

    if ignore_non_existing:
        try:
            violations.remove(SecurityStatus.DOES_NOT_EXIST)
            ignoring_non_existing = True
        except ValueError:
            # This is to allow remove when DOES_NOT_EXIST isn't in violations
            pass

    if not violations:
        violations = [SecurityStatus.OK]

    if violations != [SecurityStatus.OK]:
        violations_joined = join_securitystatus_set(",", set(violations))
        raise FilePathAuditError(f"Violated rules: {violations_joined}", path=path)

    if not ignoring_non_existing:
        Path(path).unlink()
