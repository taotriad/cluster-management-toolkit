# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Initialise the ANSIThemeStr module.
"""

from pathlib import Path, PurePath

from clustermanagementtoolkit.ansithemeprint.ansithemestr import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint.theme import set_theme
from clustermanagementtoolkit.ansithemeprint.theme import set_themepath

from clustermanagementtoolkit.cmtio import check_path
from clustermanagementtoolkit.cmtio import join_securitystatus_set

from clustermanagementtoolkit.cmtpaths import SYSTEM_DEFAULT_THEME_FILE

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks, SecurityStatus
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError

FALLBACK_THEME = {
    "term": {
        "default": "\033[0m",                           # reset
        "programname": "\033[1;37m",                    # white + bright
        "version": "\033[0;32m",                        # green
        "candidateversion": "\033[1;36m",               # cyan + bright
        # Having command the same colour as action is probably not a good choice
        "command": "\033[1;36m",                        # cyan + bright
        "option": "\033[0;36m",                         # cyan
        "argument": "\033[0;32m",                       # green
        "separator": "\033[38;5;240m",                  # grey + dim
        "description": "\033[0m",                       # reset
        "hostname": "\033[1;37m",                       # white + bright
        "path": "\033[0;36m",                           # cyan
        "uri": "\033[1;4;37m",                          # white + bright + underline
        "header": "\033[0;4;37m",                       # white + underline
        "underline": "\033[0;4;37m",                    # white + underline
        "emphasis": "\033[1;37m",                       # white + bright
        "skip": "\033[38;5;240m\033[1m",                # grey + dim + bold
        "ok": "\033[1;37m",                             # white + bright
        "notok": "\033[1;31m",                          # red + bright
        "success": "\033[1;32m",                        # green + bright
        "note": "\033[0;32m",                           # green
        "error": "\033[1;31m",                          # red + bright
        "warning": "\033[1;33m",                        # yellow + bright
        "critical": "\033[1;41;93m",                    # red + bright + inverted
        "errorvalue": "\033[0;31m",                     # red
        "phase": "\033[1;33m",                          # yellow + bright
        "action": "\033[1;36m",                         # cyan + bright
        "play": "\033[0;36m",                           # cyan
        "none": "\033[38;5;240m\033[1m",                # grey + dim + bold
        "unknown": "\033[0;31m",                        # red
        "reset": "\033[0m",                             # reset all attributes
        "yaml_list": "\033[1;33m",                      # yellow + bright
        "yaml_key": "\033[1;36m",                       # cyan + bright
        "yaml_key_separator": "\033[0;37m",             # white
        "yaml_value": "\033[0m",                        # reset
        "namespace": "\033[0;36m",                      # cyan
    }
}


def init_ansithemeprint(themefile: FilePath | None = None) -> None:
    """
    Initialise ansithemeprint.

        Parameters:
            themefile (str): Path to the theme to use
    """
    # If we get None as theme we use the builtin fallback theme
    if not themefile:
        set_theme(FALLBACK_THEME)
        set_themepath(FilePath("<built-in default>"))
        return

    # This is to allow use of ansithemeprint from cmt-install.py.
    # pylint: disable-next=import-outside-toplevel
    from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

    # If we get a theme but it doesn't exist we use the system theme file
    if themefile and not Path(themefile).is_file():
        themefile = SYSTEM_DEFAULT_THEME_FILE

    set_themepath(themefile)

    # The themes directory itself may be a symlink.
    # This is expected behaviour when installing from a git repo,
    # but we only allow it if the rest of the path components are secure
    checks = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_DIR,
    ]

    theme_dir = FilePath(PurePath(themefile).parent)

    violations = check_path(theme_dir, checks=checks)
    if violations != [SecurityStatus.OK]:
        violations_joined = join_securitystatus_set(",", set(violations))
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

    try:
        set_theme(dict(secure_read_yaml(themefile, checks=checks, asynchronous=True)))
    except TypeError:
        set_theme(FALLBACK_THEME)
        ansithemeprint([ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(": themefile ”", "default"),
                        ANSIThemeStr(f"{themefile}", "path"),
                        ANSIThemeStr("” is invalid; "
                                     "using built-in fallback theme.", "default")], stderr=True)
    except (FileNotFoundError, FilePathAuditError) as e:
        # This is equivalent to FileNotFoundError
        if "SecurityStatus.DOES_NOT_EXIST" not in str(e):
            raise
        # In practice this shouldn't happen since check_path should cover this
        set_theme(FALLBACK_THEME)
        ansithemeprint([ANSIThemeStr("Warning", "warning"),
                        ANSIThemeStr(": themefile ”", "default"),
                        ANSIThemeStr(f"{themefile}", "path"),
                        ANSIThemeStr("” does not exist; "
                                     "using built-in fallback theme.", "default")], stderr=True)
