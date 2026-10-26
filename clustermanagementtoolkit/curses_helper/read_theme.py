# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Read the theme from a file.
"""

from pathlib import Path, PurePath
from typing import cast

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtio import check_path
from clustermanagementtoolkit.cmtio import join_securitystatus_set

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmtpaths import SYSTEM_DEFAULT_THEME_FILE

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.curses_helper.themestr import ThemeStrConfiguration


def read_theme(configthemefile: FilePath, defaultthemefile: FilePath) -> None:
    """
    Read the theme file and initialise the theme dict.

        Parameters:
            configthemefile (FilePath): The theme to read
            defaultthemefile (FilePath): The fallback if the other theme is not available
    """
    for item in (configthemefile, f"{configthemefile}.yaml",
                 defaultthemefile, SYSTEM_DEFAULT_THEME_FILE):
        if item is not None and Path(item).is_file():
            ThemeStrConfiguration.themefile = cast(FilePath, item)
            break

    if ThemeStrConfiguration.themefile is None:
        if configthemefile:
            errmsg = [
                [("Failed to load themefile ", "error"),
                 (f"{configthemefile}", "path"),
                 ("; file not found.", "error")],
            ]
        elif defaultthemefile:
            errmsg = [
                [("Failed to load default themefile ", "error"),
                 (f"{defaultthemefile}", "path"),
                 ("; file not found.", "error")],
            ]
        else:
            errmsg = [
                [("Failed to load themefile; both the configthemefile "
                  + "and the defaultthemefile paths are empty", "error")],
            ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        raise ProgrammingError(unformatted_msg,
                               subexception=FileNotFoundError,
                               severity=LogLevel.ERR,
                               formatted_msg=formatted_msg)

    # The parsers directory itself may be a symlink.
    # This is expected behaviour when installing from a git repo,
    # but we only allow it if the rest of the path components are secure.
    checks = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_DIR,
    ]

    theme_dir = FilePath(PurePath(ThemeStrConfiguration.themefile).parent)

    violations = check_path(theme_dir, checks=checks)
    if violations != [SecurityStatus.OK]:
        violations_joined = join_securitystatus_set(",", set(violations))
        errmsg = [
            [("FilePathAuditError: ", "emphasis")],
            [(f"Violated rules: {violations_joined}", "error")],
            [("Path: ", "error"),
             (f"{theme_dir}", "path")],
        ]
        unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
        cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        raise FilePathAuditError(f"Violated rules: {violations_joined}", path=theme_dir)

    # We do not want to check that parent resolves to itself,
    # because when we have an installation with links directly to the git repo
    # the themes directory will be a symlink
    checks = [
        SecurityChecks.RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_FILE,
    ]

    ThemeStrConfiguration.theme = dict(secure_read_yaml(FilePath(ThemeStrConfiguration.themefile),
                                                        checks=checks, asynchronous=True))
