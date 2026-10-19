# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import errno
from getpass import getuser
from pathlib import Path, PurePath
import sys

from clustermanagementtoolkit.cmtio.check_path import check_path
from clustermanagementtoolkit.cmtio.join_securitystatus_set import join_securitystatus_set

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus


# noqa: E501 pylint: disable-next=too-many-return-statements,too-many-statements,too-many-branches,too-many-locals
def secure_symlink(src: FilePath, dst: FilePath, verbose: bool = False,
                   exit_on_failure: bool = False,
                   replace_existing: bool = False) -> list[SecurityStatus]:
    """
    Create or replace a symlink.

        Parameters:
            src (str): The path to link from
            dst (str): The path to link to
            verbose (bool): Should extra debug messages be printed?
            exit_on_failure (bool): True to exit on failure, False to return (when possible)
        Returns:
            ([SecurityStatus]): [SecurityStatus.OK] if all criteria are met,
                                otherwise a list of all violated policies
    """
    user = getuser()

    if verbose:
        print(f"Creating symbolic link {dst} pointing to {src}")

    dst_path_parent = PurePath(dst).parent
    dst_path_parent_resolved = Path(dst_path_parent).resolve()

    dst_path = Path(dst)
    src_path = Path(src)

    # Are there any path shenanigans going on?
    if dst_path_parent != dst_path_parent_resolved:
        if verbose:
            print("Critical: The target path "
                  f"{dst} does not resolve to itself; this is either a "
                  "configuration error or a security issue.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            if verbose:
                print("Aborting.", sys.stderr)
            sys.exit(errno.EINVAL)
        if verbose:
            print("Refusing to create symlink.", sys.stderr)
        return [SecurityStatus.PARENT_PATH_NOT_RESOLVING_TO_SELF]

    dst_path_parent_path = Path(dst_path_parent)

    if not dst_path_parent_path.is_dir():
        if verbose:
            print("Error: The parent of the target path "
                  f"{dst} is not a directory.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            if verbose:
                print("Aborting.", sys.stderr)
            sys.exit(errno.EINVAL)
        if verbose:
            print("Refusing to create symlink.", sys.stderr)
        return [SecurityStatus.PARENT_IS_NOT_DIR]

    if dst_path_parent_path.owner() not in ("root", user):
        if verbose:
            print("Error: The parent of the target path "
                  f"{dst} is not owned by root or {user}.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            if verbose:
                print("Aborting.", sys.stderr)
            sys.exit(errno.EINVAL)
        if verbose:
            print("Refusing to create symlink.", sys.stderr)
        return [SecurityStatus.PARENT_OWNER_NOT_IN_ALLOWLIST]

    parent_path_stat = dst_path_parent_path.stat()
    parent_path_permissions = parent_path_stat.st_mode & 0o002

    if parent_path_permissions != 0:
        print("Critical: The parent of the target path "
              f"{dst} is world writable.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            if verbose:
                print("Aborting.", sys.stderr)
            sys.exit(errno.EINVAL)
        if verbose:
            print("Refusing to create symlink.", sys.stderr)
        return [SecurityStatus.PARENT_PERMISSIONS]

    # Verify that the source path exists and that the owner and permissions are reliable;
    # we do not make further assumptions.
    checks: list[SecurityChecks] = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.RESOLVES_TO_SELF,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.EXISTS,
    ]

    violations = check_path(FilePath(src_path), checks=checks)

    if violations != [SecurityStatus.OK]:
        violations_joined = join_securitystatus_set(",", set(violations))
        if verbose:
            print("Critical: The source path "
                  f"{src} violates the following security checks "
                  f"[{violations_joined}]; this is either a "
                  "configuration error or a security issue.", sys.stderr)
        if exit_on_failure:  # pragma: no cover
            if verbose:
                print("Aborting.", sys.stderr)
            sys.exit(errno.EINVAL)
        if verbose:
            print("Refusing to create symlink.", sys.stderr)
        return violations

    # Since the parent path resolves safely, we can unlink dst_path if it is a symlink
    if dst_path.is_symlink():
        if not replace_existing:
            if verbose:
                print("Critical: The source path "
                      f"{src} exists and replace_existing=False.", sys.stderr)
            if exit_on_failure:  # pragma: no cover
                if verbose:
                    print("Aborting.", sys.stderr)
                sys.exit(errno.EEXIST)
            if verbose:
                print("Refusing to create symlink.", sys.stderr)
            return [SecurityStatus.EXISTS]

        dst_path.unlink()

    try:
        dst_path.symlink_to(src_path)
    except FileExistsError:
        return [SecurityStatus.EXISTS]
    return [SecurityStatus.OK]
