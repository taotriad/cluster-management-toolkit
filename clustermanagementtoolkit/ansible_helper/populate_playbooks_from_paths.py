# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from pathlib import PurePath
import re

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmtio import check_path, join_securitystatus_set
from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks, SecurityStatus
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError


# Add all playbooks in the array
def populate_playbooks_from_paths(paths: list[FilePath]) -> list[tuple[list[ANSIThemeStr],
                                                                       FilePath]]:
    """
    Populate a list of playbook paths.

        Parameters:
            paths ([FilePath]): A list of paths to playbooks
        Returns:
            [([ANSIThemeStr], FilePath)]:
                ([ANSIThemeStr]): An ansithemearray with the name of the playbook
                (FilePath): The path to the playbook
        Raises:
            FilePathAuditError: The playbook exists but violates path constraints
    """
    playbooks = []

    yaml_regex = re.compile(r"^(.*)\.ya?ml$")

    for playbookpath in paths:
        pathname = PurePath(playbookpath).name
        playbook_dir = FilePath(PurePath(playbookpath).parent)

        # Do not process backups, etc.
        if pathname.startswith(("~", ".")):
            continue

        # Only process playbooks
        if (re_tmp := yaml_regex.match(pathname)) is None:
            raise ValueError(f"The playbook filename “{pathname}“ does not end with "
                             ".yaml or .yml; this is most likely a programming error.")

        playbookname = re_tmp[1]

        # The playbook directory itself may be a symlink.
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

        if (violations := check_path(playbook_dir, checks=checks)) != [SecurityStatus.OK]:
            violations_joined = join_securitystatus_set(",", set(violations))
            raise FilePathAuditError(f"Violated rules: {violations_joined}", path=playbook_dir)

        # We do not want to check that parent resolves to itself,
        # because when we have an installation with links directly to the git repo
        # the playbooks directory will be a symlink
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
            dl = list(secure_read_yaml(playbookpath, checks=checks))
        except TypeError:
            dl = []
        description = None
        if (t_description := deep_get(dl[0], DictPath("vars#metadata#description"), "")):
            description = [ANSIThemeStr(t_description, "play")]

        if description is None or not description:
            description = [ANSIThemeStr("Running “", "play"),
                           ANSIThemeStr(playbookname, "programname"),
                           ANSIThemeStr("“", "play")]

        # If there's no description we fallback to just using the filename
        playbooks.append(([ANSIThemeStr("  • ", "separator")] + description, playbookpath))
    return playbooks
