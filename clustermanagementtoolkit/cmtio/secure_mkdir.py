# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Create a directory in a secure manner.
"""

import errno
from getpass import getuser
from pathlib import Path
import sys

from clustermanagementtoolkit.cmtio.check_path import check_path

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus


def secure_mkdir(directory: FilePath, permissions: int = 0o750, verbose: bool = False,
                 exist_ok: bool = True, exit_on_failure: bool = False) -> list[SecurityStatus]:
    """
    Create a directory if it does not already exist.

        Parameters:
            directory (str): The path to the directory to create
            permissions (int): File permissions (None uses system defaults)
            verbose (bool): Should extra debug messages be printed?
            exit_on_failure (bool): True to exit on failure, False to return (when possible)
        Returns:
            ([SecurityStatus]): [SecurityStatus.OK] if all criteria are met,
                                otherwise a list of all violated policies
    """
    if verbose:
        print(f"Creating directory {directory}"
              f" with permissions {permissions:03o}")

    user = getuser()

    violations = check_path(directory, message_on_error=verbose,
                            parent_owner_allowlist=[user, "root"],
                            owner_allowlist=[user],
                            checks=[
                                SecurityChecks.PARENT_RESOLVES_TO_SELF,
                                SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
                                SecurityChecks.OWNER_IN_ALLOWLIST,
                                SecurityChecks.PARENT_PERMISSIONS,
                                SecurityChecks.PERMISSIONS,
                                SecurityChecks.EXISTS,
                                SecurityChecks.IS_DIR,
                            ],
                            exit_on_critical=exit_on_failure)

    if SecurityStatus.PARENT_DOES_NOT_EXIST in violations:
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.ENOENT)
        return violations

    if SecurityStatus.PARENT_IS_NOT_DIR in violations:
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.EINVAL)
        return violations

    if SecurityStatus.DOES_NOT_EXIST not in violations and SecurityStatus.IS_NOT_DIR in violations:
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.EEXIST)
        return violations

    # These are the only acceptable conditions where we'd try to create the directory
    if violations in ([SecurityStatus.OK], [SecurityStatus.DOES_NOT_EXIST]):
        violations = []
        try:
            Path(directory).mkdir(mode=permissions, exist_ok=exist_ok)
        except FileExistsError:
            violations.append(SecurityStatus.EXISTS)
        if not violations:
            violations.append(SecurityStatus.OK)

    return violations
