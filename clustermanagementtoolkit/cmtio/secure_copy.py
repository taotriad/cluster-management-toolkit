# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Copy a file in a secure manner.
"""

import errno
import os
from functools import partial
from pathlib import Path, PurePath
import sys

from clustermanagementtoolkit.cmtio.check_path import check_path
from clustermanagementtoolkit.cmtio.join_securitystatus_set import join_securitystatus_set

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus


# pylint: disable-next=too-many-branches
def secure_copy(src: FilePath, dst: FilePath, verbose: bool = False,
                exit_on_failure: bool = False,
                permissions: int | None = None) -> list[SecurityStatus]:
    """
    Copy a file.

        Parameters:
            src (str): The path to copy from
            dst (str): The path to copy to
            verbose (bool): Should extra debug messages be printed?
            exit_on_failure (bool): True to exit on failure, False to return (when possible)
            permissions (int): The file permissions to use (None to use system defaults)
        Returns:
            ([SecurityStatus]): [SecurityStatus.OK] if all criteria are met,
                                                    otherwise a list of all violated policies
    """
    if verbose:
        print(f"Copying file {src} to {dst}")

    # Are there any path shenanigans going on?
    checks: list[SecurityChecks] = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.RESOLVES_TO_SELF,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_FILE,
    ]

    violations = check_path(src, checks=checks)
    if violations != [SecurityStatus.OK]:
        if verbose:
            violations_joined = join_securitystatus_set(",", set(violations))
            print(f"Critical: The source path {src}"
                  " violates the following security checks "
                  f"[{violations_joined}]; this is either a "
                  "configuration error or a security issue.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.EINVAL)
        return violations

    # Are there any path shenanigans going on?
    checks = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.RESOLVES_TO_SELF,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.IS_DIR,
    ]

    dst_path_parent = PurePath(dst).parent
    violations = check_path(FilePath(PurePath(dst).parent), checks=checks)

    if violations != [SecurityStatus.OK]:
        if verbose:
            violations_joined = join_securitystatus_set(",", set(violations))
            print(f"Critical: The target path {dst_path_parent}"
                  " violates the following security checks "
                  f"[{violations_joined}]; this is either a "
                  "configuration error or a security issue.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.EINVAL)
        return violations

    dst_path = Path(dst)

    if dst_path.exists():
        if verbose:
            print(f"Error: The target path {dst}"
                  " already exists; refusing to overwrite.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.EINVAL)
        return [SecurityStatus.EXISTS]

    # We do not need to inspect the content, so open it in binary mode
    # We should not need "xb", since we have already checked that dst does not exist,
    # but better be safe than sorry
    try:
        if permissions is None:
            with open(src, "rb") as fr, open(dst, "xb") as fw:
                content = fr.read()
                fw.write(content)
        else:
            with open(src, "rb") as fr, open(dst, "xb",
                                             opener=partial(os.open, mode=permissions)) as fw:
                content = fr.read()
                fw.write(content)
    except PermissionError:
        if verbose:
            print(f"Error: The target path {dst}"
                  " cannot be written to (Permission denied).", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            sys.exit(errno.EINVAL)
        return [SecurityStatus.PERMISSIONS]

    return [SecurityStatus.OK]
