# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A checker that verifies security conditions for a path.
"""

import errno
from getpass import getuser
import os
from pathlib import Path, PurePath
import sys
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-statements,too-many-locals,too-many-branches
def check_path(path: FilePath, **kwargs: Any) -> list[SecurityStatus]:
    """
    Verifies that a path meets certain security criteria;
    if the path fails to meet the criteria the function returns False and optionally
    outputs an error message. Critical errors will either raise an exception or exit the program.

        Parameters:
            path (FilePath): The path to the file to verify
            **kwargs (dict[str, Any]): Keyword arguments
                parent_allowlist ([str]): A list of acceptable file owners;
                                          by default [user, "root"]
                owner_allowlist ([str]): A list of acceptable file owners;
                                         by default [user, "root"]
                checks ([SecurityChecks]): A list of checks that should be performed
                exit_on_critical (bool): By default check_path returns SecurityStatus
                                         if a critical criteria violation is found;
                                         this flag can be used to exit the program
                                         instead if the violation is critical
                message_on_error (bool): If this is set to true an error message
                                         will be printed to the console
        Returns:
            ([SecurityStatus]): [SecurityStatus.OK] if all criteria are met,
                                otherwise a list of all violated policies
    """
    parent_owner_allowlist: list[str] | None = \
        deep_get(kwargs, DictPath("parent_owner_allowlist"), None)
    owner_allowlist: list[str] | None = \
        deep_get(kwargs, DictPath("owner_allowlist"), None)
    checks: list[SecurityChecks] | None = deep_get(kwargs, DictPath("checks"), None)
    exit_on_critical: bool = deep_get(kwargs, DictPath("exit_on_critical"), False)
    message_on_error: bool = deep_get(kwargs, DictPath("message_on_error"), False)

    # This is most likely a security violation; treat it as such.
    if "\x00" in path:
        stripped_path = path.replace("\x00", "<NUL>")
        raise ValueError(f"Critical: the path {stripped_path} contains NUL-bytes:\n"
                         "This is either a programming error, a system error, "
                         "file or memory corruption, "
                         "or a deliberate attempt to bypass security; aborting.")

    violations = []

    if checks is None:
        # These are the default checks for a file.
        checks = [
            SecurityChecks.PARENT_RESOLVES_TO_SELF,
            SecurityChecks.OWNER_IN_ALLOWLIST,
            SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
            SecurityChecks.PERMISSIONS,
            SecurityChecks.PARENT_PERMISSIONS,
            SecurityChecks.EXISTS,
            SecurityChecks.IS_FILE,
        ]

    user = getuser()

    if parent_owner_allowlist is None:
        parent_owner_allowlist = [user, "root"]

    if owner_allowlist is None:
        owner_allowlist = [user, "root"]

    path_entry = Path(path)
    parent_entry = Path(PurePath(path).parent)

    # This test is not optional; if the parent directory does not exist it is always a failure
    if not parent_entry.exists():
        if message_on_error:
            msg = "Critical: The parent of the target path " \
                  f"{path} does not exist"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, file=sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PARENT_DOES_NOT_EXIST)
        return violations

    if not parent_entry.is_dir():
        if message_on_error:
            msg = "Critical: The parent of the target path " \
                  f"{path} exists but is not a directory; " \
                  "this is either a configuration error " \
                  "or a security issue"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PARENT_IS_NOT_DIR)
        return violations

    if SecurityChecks.PARENT_OWNER_IN_ALLOWLIST in checks \
            and parent_entry.owner() not in parent_owner_allowlist:
        if message_on_error:
            msg = "Critical: The parent of the target path " \
                  f"{path} is not owned by one of (" \
                  + ", ".join(parent_owner_allowlist) + ")"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PARENT_OWNER_NOT_IN_ALLOWLIST)

    parent_path_stat = parent_entry.stat()
    parent_path_permissions = parent_path_stat.st_mode & 0o002
    if SecurityChecks.PARENT_PERMISSIONS in checks and parent_path_permissions != 0:
        if message_on_error:
            msg = "Critical: The parent of the target path " \
                  f"{path} is world writable"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PARENT_PERMISSIONS)

    parent_entry_resolved = parent_entry.resolve()
    parent_entry_systemdir = False
    if str(parent_entry) in ("/bin", "/sbin", "/usr/bin", "/usr/sbin") \
            and str(parent_entry_resolved) in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
        parent_entry_systemdir = True

    # Are there any path shenanigans going on?  If we are dealing with
    # {/bin,/sbin,/usr/bin,/usr/sbin}/path => {/bin,/sbin,/usr/bin,/usr/sbin}/path
    # the symlink is acceptable.
    if SecurityChecks.PARENT_RESOLVES_TO_SELF in checks \
            and parent_entry != parent_entry_resolved and not parent_entry_systemdir:
        if message_on_error:
            msg = "Critical: The parent of the target path " \
                  f"{path} does not resolve to itself; this is either a " \
                  "configuration error or a security issue"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PARENT_PATH_NOT_RESOLVING_TO_SELF)

    # Are there any path shenanigans going on?  We first resolve the parent path,
    # then check the rest; this way we can see if the target is a symlink and see
    # where it ends up.
    name = path_entry.name
    tmp_entry = Path(os.path.join(parent_entry_resolved, name))

    if SecurityChecks.RESOLVES_TO_SELF in checks and tmp_entry != tmp_entry.resolve():
        if message_on_error:
            msg = "Critical: The target path " \
                  f"{path} does not resolve to itself; this is either a " \
                  "configuration error or a security issue"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PATH_NOT_RESOLVING_TO_SELF)

    if not path_entry.exists():
        if SecurityChecks.EXISTS in checks:
            violations.append(SecurityStatus.DOES_NOT_EXIST)
        if not violations:
            violations = [SecurityStatus.OK]
        return violations

    if SecurityChecks.OWNER_IN_ALLOWLIST in checks and path_entry.owner() not in owner_allowlist:
        if message_on_error:
            msg = f"Critical: The target path {path} is not owned by one of (" \
                  + ", ".join(owner_allowlist) + ")"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.OWNER_NOT_IN_ALLOWLIST)

    path_stat = path_entry.stat()
    path_permissions = path_stat.st_mode & 0o002
    if path_permissions != 0:
        if message_on_error:
            msg = f"Critical: The target path {path} is world writable"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PERMISSIONS)

    if path_entry.exists() and SecurityChecks.PERMISSIONS in checks \
            and not os.access(path, os.R_OK):
        if message_on_error:
            msg = f"Critical: The target path {path} cannot be read"
            if exit_on_critical:  # pragma: no cover
                msg += "; aborting."
                print(msg, sys.stderr)
                sys.exit(errno.EINVAL)
            print(msg, sys.stderr)
        violations.append(SecurityStatus.PERMISSIONS)

    if SecurityChecks.IS_SYMLINK in checks and not path_entry.is_symlink():
        if message_on_error:
            msg = f"Error: The target path {path}" \
                  " exists but is not a symlink; this is either a " \
                  "configuration error or a security issue"
            print(msg, sys.stderr)
        violations.append(SecurityStatus.IS_NOT_SYMLINK)

    # is_file() returns True even if path is a symlink to a file rather than a file
    if SecurityChecks.IS_FILE in checks and not path_entry.is_file():
        if message_on_error:
            msg = f"Error: The target path {path}" \
                  " exists but is not a file; this is either a " \
                  "configuration error or a security issue"
            print(msg, sys.stderr)
        violations.append(SecurityStatus.IS_NOT_FILE)

    # is_file() returns True even if path is a symlink to a file rather than a file
    if SecurityChecks.IS_DIR in checks and not path_entry.is_dir():
        if message_on_error:
            msg = f"Error: The target path {path}" \
                  " exists but is not a directory; this is either a " \
                  "configuration error or a security issue"
            print(msg, sys.stderr)
        violations.append(SecurityStatus.IS_NOT_DIR)

    if SecurityChecks.IS_NOT_EXECUTABLE in checks \
            and os.access(path, os.X_OK) and not path_entry.is_dir():
        if message_on_error:
            msg = f"Warning: The target path {path}" \
                  " is executable but should not be; skipping"
            print(msg, sys.stderr)
        violations.append(SecurityStatus.IS_EXECUTABLE)

    if SecurityChecks.IS_EXECUTABLE in checks and not os.access(path, os.X_OK):
        if message_on_error:
            msg = f"Warning: The target path {path}" \
                  " exists but is not executable; skipping"
            print(msg, sys.stderr)
        violations.append(SecurityStatus.IS_NOT_EXECUTABLE)

    if not violations:
        violations = [SecurityStatus.OK]

    return violations
