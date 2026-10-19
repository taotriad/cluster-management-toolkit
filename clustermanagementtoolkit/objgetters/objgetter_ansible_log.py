# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return an object constructed from the log of an Ansible play.
"""

from pathlib import Path, PurePath
import sys
from typing import Any, cast

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmtio import check_path
from clustermanagementtoolkit.cmtio import join_securitystatus_set

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import SecurityStatus
from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import FilePathAuditError


def objgetter_ansible_log(path: FilePath) -> dict:
    """
    Get an obj from an Ansible log entry.

        Parameters:
            obj (FilePath): The path to the ansible log
        Returns:
            (dict): An ansible log entry
    """
    tmpobj: dict[str, Any] = cast(dict, secure_read_yaml(path.joinpath("metadata.yaml")))
    tmpobj["log_path"] = str(path)

    # The playbook directory itself may be a symlink.
    # This is expected behaviour when installing from a git repo,
    # but we only allow it if the rest of the path components are secure
    checks: list[SecurityChecks] = [
        SecurityChecks.PARENT_RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_DIR,
    ]

    playbook_path = FilePath(tmpobj["playbook_path"])
    playbook_dir = FilePath(PurePath(playbook_path).parent)

    violations = check_path(playbook_dir, checks=checks)
    if violations != [SecurityStatus.OK]:
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
        SecurityChecks.IS_FILE,
    ]
    try:
        playbook = secure_read_yaml(playbook_path, checks=checks)
        tmpobj["name"] = deep_get(playbook[0], DictPath("vars#metadata#description"))
        tmpobj["playbook_types"] = deep_get(playbook[0],
                                            DictPath("vars#metadata#playbook_types"), ["<any>"])
        tmpobj["category"] = deep_get(playbook[0],
                                      DictPath("vars#metadata#category"), "Uncategorized")
    except FileNotFoundError:
        tmpobj["name"] = "File not found"
        tmpobj["playbook_types"] = ["Unavailable"]
        tmpobj["category"] = "Unavailable"

    logs = []
    for entry in natsorted(Path(str(path)).iterdir()):
        if (filename := PurePath(str(entry)).name) == "metadata.yaml":
            continue
        log = secure_read_yaml(FilePath(str(entry)))
        logs.append({
            "index": filename.split("-", maxsplit=1)[0],
            "log": log
        })
    tmpobj["logs"] = logs

    return tmpobj
