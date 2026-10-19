# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from pathlib import Path

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmtpaths import HOMEDIR
from clustermanagementtoolkit.cmtpaths import ANSIBLE_PLAYBOOKS_DIR
from clustermanagementtoolkit.cmtpaths import SYSTEM_ANSIBLE_PLAYBOOKS_DIR

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError


def get_playbook_path(playbook: FilePath | str) -> FilePath:
    """
    Pass in the name of a playbook that exists in either
    {SYSTEM_ANSIBLE_PLAYBOOKS_DIR} or {ANSIBLE_PLAYBOOKS_DIR};
    returns the path to the drop-in playbook with the highest priority
    (or the same playbook in case there is no override).

        Parameters:
            playbook (FilePath): The name of the playbook to get the path to
        Returns:
            (FilePath): The playbook path with the highest priority
        Raises:
            FilePathAuditError: No usable match playbook was found
    """
    path = ""

    if not isinstance(playbook, (FilePath, str)):
        raise TypeError(f"playbook is type: {type(playbook)}, expected FilePath | str")
    if not playbook:
        raise ValueError("len(playbook) == 0; expected a filename")

    # Check if there's a local playbook overriding this one
    playbook_dirs = deep_get(cmtlib.cmtconfig, DictPath("Ansible#local_playbooks"), [])
    playbook_dirs.append(ANSIBLE_PLAYBOOKS_DIR)
    playbook_dirs.append(SYSTEM_ANSIBLE_PLAYBOOKS_DIR)

    for playbook_path in playbook_dirs:
        # Substitute {HOME}/ for {HOMEDIR}
        if playbook_path.startswith("{HOME}/"):
            playbook_path = f"{HOMEDIR}/{playbook_path[len('{HOME}/'):]}"
        playbook_path_entry = Path(playbook_path)
        # Skip non-existing playbook paths
        if not playbook_path_entry.is_dir():
            continue
        # We can have multiple directories with playbooks;
        # the first match wins
        if Path(f"{playbook_path}/{playbook}").is_file():
            path = f"{playbook_path}/{playbook}"
            break
    if not path:
        raise FilePathAuditError(f"Could not find a usable match for playbook `{playbook}`",
                                 path=playbook)
    return FilePath(path)
