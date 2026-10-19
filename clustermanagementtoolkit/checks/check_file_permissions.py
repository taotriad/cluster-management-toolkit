# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from collections.abc import Generator, Sequence
import errno
from pathlib import Path
import sys
from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.recommended_permissions import DirectoryPermissions
from clustermanagementtoolkit.recommended_permissions import FilePermissions
from clustermanagementtoolkit.recommended_permissions import recommended_directory_permissions
from clustermanagementtoolkit.recommended_permissions import recommended_file_permissions


# pylint: disable-next=too-many-statements,too-many-locals,too-many-branches
def __check_permissions(recommended_permissions: Sequence[DirectoryPermissions | FilePermissions],
                        pathtype: str, **kwargs: Any) -> tuple[bool, bool, int, int, int, int]:
    """
    Check permissions for a path.

        Parameters:
            recommended_permissions ([dict]): A list of dicts with the path to check,
                                              the recommended permissions,
                                              severity, justification, etc.
            pathtype (str): The type of the path
            **kwargs (dict[str, Any]): Keyword arguments
                user (str): Username of the executing user
                usergroup (str): The usergroup to check against
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
        Returns:
            (issue, critical, error, warning, note):
                issue (bool): Found a security issue
                critical (int): The new count of critical severity security issues
                error (int): The new count of error severity security issues
                warning (int): The new count of warning severity security issues
                note (int): The new count of note severity security issues
            (bool, bool, int, int, int, int):
                (bool): Should we abort?
                (bool): Found a security issue
                (int): The new count of critical severity security issues
                (int): The new count of error severity security issues
                (int): The new count of warning severity security issues
                (int): The new count of note severity security issues
    """
    user: str = deep_get(kwargs, DictPath("user"), "")
    usergroup: str = deep_get(kwargs, DictPath("usergroup"), "")
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)

    issue = False
    abort = False

    if not user or not usergroup:
        raise ProgrammingError(f"{__name__}() called without user and/or usergroup")

    for permissions in recommended_permissions:
        path = deep_get(permissions, DictPath("path"))
        alertmask = deep_get(permissions, DictPath("alertmask"), 0o077)
        usergroup_alertmask = deep_get(permissions, DictPath("usergroup_alertmask"), alertmask)
        severity = deep_get(permissions, DictPath("severity"), "critical")
        tmp_justification = deep_get(permissions, DictPath("justification"),
                                     [("<no justification provided>", "emphasis")])
        justification = ANSIThemeStr.tuplelist_to_ansithemearray(tmp_justification)
        executable = deep_get(permissions, DictPath("executable"), False)
        suffixes = deep_get(permissions, DictPath("suffixes"))
        optional = deep_get(permissions, DictPath("optional"), False)

        if usergroup:
            alertmask = usergroup_alertmask
        notemask = 0o000
        if pathtype == "file" and not executable:
            notemask = 0o111

        path_entry = Path(path)

        if path_entry.exists():
            # If this is a directory, but we operate on files we should apply these tests
            # for every matching file in this directory
            paths: list[Path] | Generator[Path, None, None] = []

            if pathtype == "file" and path_entry.is_dir():
                paths = path_entry.iterdir()
            else:
                paths = [path_entry]

            for entry in paths:
                if pathtype == "file":
                    if not entry.is_file() and not entry.is_symlink():
                        continue

                    if suffixes is not None and not str(entry).endswith(suffixes):
                        continue

                try:
                    # pylint: disable-next=assignment-from-no-return
                    path_owner = entry.owner()
                except KeyError:
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Critical", "error"),
                                    ANSIThemeStr(":", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr(f"    The owner of the {pathtype} ",
                                                 "default"),
                                    ANSIThemeStr(f"{entry}", "path"),
                                    ANSIThemeStr(" does not exist in the system database; "
                                                 "aborting.", "default")], stderr=True)
                    sys.exit(errno.ENOENT)

                try:
                    # pylint: disable-next=assignment-from-no-return
                    path_group = entry.group()
                except KeyError:
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Critical", "error"),
                                    ANSIThemeStr(":", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr(f"    The group of the {pathtype} ", "default"),
                                    ANSIThemeStr(f"{entry}", "path"),
                                    ANSIThemeStr(" does not exist in the system database; "
                                                 "aborting.", "default")], stderr=True)
                    sys.exit(errno.ENOENT)

                path_stat = entry.stat()
                path_permissions = path_stat.st_mode & 0o777
                recommended_permissions = 0o777 & ~(alertmask | notemask)

                if path_owner not in (user, "root"):
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Critical", severity),
                                    ANSIThemeStr(f": The {pathtype} ", "default"),
                                    ANSIThemeStr(f"{entry}", "path"),
                                    ANSIThemeStr(" is not owned by ", "default"),
                                    ANSIThemeStr(user, "emphasis")], stderr=True)
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Justification", "emphasis"),
                                    ANSIThemeStr(": if other users can overwrite files they "
                                                 "may be able to achieve elevated "
                                                 "privileges", "default")], stderr=True)
                    critical += 1
                    issue = True

                if usergroup and path_group != usergroup:
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Critical", severity),
                                    ANSIThemeStr(f": The {pathtype} ", "default"),
                                    ANSIThemeStr(f"{entry}", "path"),
                                    ANSIThemeStr(" does not belong to the user group for ",
                                                 "default"),
                                    ANSIThemeStr(user, "emphasis")], stderr=True)
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Justification", "emphasis"),
                                    ANSIThemeStr(": ", "default")] + justification,
                                   stderr=True)
                    print()
                    critical += 1
                    issue = True

                if path_permissions & alertmask != 0:
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr(f"{severity.capitalize()}", severity),
                                    ANSIThemeStr(":", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr(f"    The permissions for the {pathtype} ",
                                                 "default"),
                                    ANSIThemeStr(f"{entry}", "path"),
                                    ANSIThemeStr(" are ", "default"),
                                    ANSIThemeStr(f"{path_permissions:03o}", "emphasis"),
                                    ANSIThemeStr(";", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr("    the recommended permissions are ",
                                                 "default"),
                                    ANSIThemeStr(f"{recommended_permissions:03o}", "emphasis"),
                                    ANSIThemeStr(" (or stricter).", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Justification", "emphasis"),
                                    ANSIThemeStr(": ", "default")], stderr=True)
                    ansithemeprint(justification, stderr=True)
                    print()

                    if severity == "critical":
                        critical += 1
                        issue = True
                    elif severity == "error":
                        error += 1
                        issue = True
                    elif severity == "warning":
                        warning += 1
                        issue = True
                    elif severity == "note":
                        note += 1
                        issue = True

                if path_permissions & notemask != 0:
                    ansithemeprint([ANSIThemeStr("  ", "default"),
                                    ANSIThemeStr("Note", "note"),
                                    ANSIThemeStr(":", "default")])
                    ansithemeprint([ANSIThemeStr("    The permissions for the "
                                                 f"{pathtype} ", "default"),
                                    ANSIThemeStr(f"{entry}", "path"),
                                    ANSIThemeStr(" are ", "default"),
                                    ANSIThemeStr(f"{path_permissions:03o}", "emphasis"),
                                    ANSIThemeStr("; this file is not an executable and should "
                                                 "not have the executable bit set", "default")])
        else:
            if not optional:
                ansithemeprint([ANSIThemeStr("  ", "default"),
                                ANSIThemeStr("Warning", "warning"),
                                ANSIThemeStr(":", "default")], stderr=True)
                ansithemeprint([ANSIThemeStr(f"    The {pathtype} ", "default"),
                                ANSIThemeStr(f"{path}", "path"),
                                ANSIThemeStr(" does not exist; skipping.\n",
                                             "default")], stderr=True)
                warning += 1
                issue = True
            continue

    return abort, issue, critical, error, warning, note


def check_file_permissions(**kwargs: Any) -> tuple[bool, int, int, int, int]:
    """
    This checks whether any files or directories have insecure permissions.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                user (str): Username of the executing user
                usergroup (str): The usergroup of the user
                kubeconfig (dict)): The kubeconfig file
                cmtconfig_dict (dict): The cmtconfig file
                critical (int): The current count of critical severity security issues
                error (int): The current count of error severity security issues
                warning (int): The current count of warning severity security issues
                note (int): The current count of note severity security issues
        Returns:
            (bool, int, int, int, int):
                (bool): Is this error severe enough that we should abort immediately?
                (int): The new count of critical severity security issues
                (int): The new count of error severity security issues
                (int): The new count of warning severity security issues
                (int): The new count of note severity security issues
    """
    user: str = deep_get(kwargs, DictPath("user"), "")
    usergroup = deep_get(kwargs, DictPath("usergroup"), "")
    critical: int = deep_get(kwargs, DictPath("critical"), 0)
    error: int = deep_get(kwargs, DictPath("error"), 0)
    warning: int = deep_get(kwargs, DictPath("warning"), 0)
    note: int = deep_get(kwargs, DictPath("note"), 0)

    abort = False

    if not user or not usergroup:
        raise ProgrammingError(f"{__name__}() called without user and/or usergroup")

    ansithemeprint([ANSIThemeStr("[Checking directory and file permissions]", "phase")])

    abort, issue, critical, error, warning, note = \
        __check_permissions(recommended_directory_permissions, "directory",
                            user=user, usergroup=usergroup,
                            critical=critical, error=error, warning=warning, note=note)
    abort, issue, critical, error, warning, note = \
        __check_permissions(recommended_file_permissions, "file",
                            user=user, usergroup=usergroup,
                            critical=critical, error=error, warning=warning, note=note)

    if not issue:
        ansithemeprint([ANSIThemeStr("  OK\n", "emphasis")])

    return abort, critical, error, warning, note
