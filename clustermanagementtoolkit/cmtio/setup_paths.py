# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Create all paths needed by CMT.
"""

from pathlib import Path
import sys

from clustermanagementtoolkit.cmtio.secure_mkdir import secure_mkdir

from clustermanagementtoolkit.cmtpaths import ANSIBLE_DIR
from clustermanagementtoolkit.cmtpaths import ANSIBLE_LOGS_DIR
from clustermanagementtoolkit.cmtpaths import ANSIBLE_PLAYBOOKS_DIR
from clustermanagementtoolkit.cmtpaths import CMT_CONFIG_FILE_DIR
from clustermanagementtoolkit.cmtpaths import CMTDIR
from clustermanagementtoolkit.cmtpaths import CMT_HOOKS_DIR
from clustermanagementtoolkit.cmtpaths import CMT_LOGS_DIR
from clustermanagementtoolkit.cmtpaths import CMT_POST_PREPARE_DIR
from clustermanagementtoolkit.cmtpaths import CMT_POST_PURGE_DIR
from clustermanagementtoolkit.cmtpaths import CMT_POST_SETUP_DIR
from clustermanagementtoolkit.cmtpaths import CMT_POST_TEARDOWN_DIR
from clustermanagementtoolkit.cmtpaths import CMT_POST_UPGRADE_DIR
from clustermanagementtoolkit.cmtpaths import CMT_PRE_PREPARE_DIR
from clustermanagementtoolkit.cmtpaths import CMT_PRE_PURGE_DIR
from clustermanagementtoolkit.cmtpaths import CMT_PRE_SETUP_DIR
from clustermanagementtoolkit.cmtpaths import CMT_PRE_UPGRADE_DIR
from clustermanagementtoolkit.cmtpaths import DEPLOYMENTS_DIR
from clustermanagementtoolkit.cmtpaths import PARSERS_DIR
from clustermanagementtoolkit.cmtpaths import SOFTWARE_SOURCES_DIR
from clustermanagementtoolkit.cmtpaths import SYSTEM_DATA_DIR
from clustermanagementtoolkit.cmtpaths import THEMES_DIR
from clustermanagementtoolkit.cmtpaths import VERSION_CACHE_DIR
from clustermanagementtoolkit.cmtpaths import VIEWS_DIR

from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import SecurityStatus

# The following paths are necessary:
# ${HOMEDIR}
# └── .cmt (main directory for CMT)
#     ├── ansible (Ansible files)
#     │   └── log (Ansible logs)
#     ├── cmt.yaml.d (configlets)
#     ├── deployments (generic workloads)
#     ├── hooks (installation hooks)
#     │   └── pre-prepare.d (hooks run before the prepare step)
#     │   ├── post-prepare.d (hooks run after the prepare step)
#     │   ├── pre-setup.d (hooks run before the setup step)
#     │   ├── post-setup.d (hooks run after the setup step)
#     │   ├── pre-upgrade.d (hooks run before the upgrade step)
#     │   ├── post-upgrade.d (hooks run after the upgrade step)
#     │   ├── pre-teardown.d (hooks run before the teardown step)
#     │   ├── post-teardown.d (hooks run after the teardown step)
#     │   ├── pre-purge.d (hooks run before the purge step)
#     │   └── post-purge.d (hooks run after the purge step)
#     ├── logs (debug logs)
#     ├── parsers (parser files; symlink if cmt-install.py, dir when system path)
#     ├── playbooks (Ansible playbooks; symlink if cmt-install.py, dir when system path)
#     ├── sources (data sources; symlink if cmt-install.py, dir when system path)
#     ├── themes (theme files; symlink if cmt-install.py, dir when system path)
#     ├── version-cache (version data cache)
#     └── views (view files; symlink if cmt-install.py, dir when system path)
#
required_dir_paths: list[tuple[FilePath, int]] = [
    (CMTDIR, 0o755),
    (ANSIBLE_DIR, 0o755),
    (ANSIBLE_LOGS_DIR, 0o700),
    (CMT_CONFIG_FILE_DIR, 0o755),
    (DEPLOYMENTS_DIR, 0o700),
    (CMT_HOOKS_DIR, 0o755),
    (CMT_PRE_PREPARE_DIR, 0o755),
    (CMT_POST_PREPARE_DIR, 0o755),
    (CMT_PRE_SETUP_DIR, 0o755),
    (CMT_POST_SETUP_DIR, 0o755),
    (CMT_PRE_UPGRADE_DIR, 0o755),
    (CMT_POST_UPGRADE_DIR, 0o755),
    (CMT_POST_TEARDOWN_DIR, 0o755),
    (CMT_POST_TEARDOWN_DIR, 0o755),
    (CMT_PRE_PURGE_DIR, 0o755),
    (CMT_POST_PURGE_DIR, 0o755),
    (CMT_LOGS_DIR, 0o700),
    (VERSION_CACHE_DIR, 0o700),
]

required_dir_or_symlink_paths: list[tuple[FilePath, int]] = [
    (ANSIBLE_PLAYBOOKS_DIR, 0o755),
    (PARSERS_DIR, 0o755),
    (SOFTWARE_SOURCES_DIR, 0o755),
    (THEMES_DIR, 0o755),
    (VIEWS_DIR, 0o755),
]


def setup_paths() -> list[SecurityStatus]:
    """
    Create all directories & files that need to be present
    for CMT to work properly; this should've been handled by ./cmt-install.py
    if we're running directly from git + ${HOMEDIR}/bin.

    If /usr/share/cluster-management-toolkit doesn't exist we assume local installation;
    this heuristic may need revisiting later on.

        Returns:
            ([SecurityStatus]): SecurityStatus.OK on success,
                                a list of SecurityStatus violations on failure
    """
    system_path_installation = True

    if not Path(SYSTEM_DATA_DIR).is_dir():
        system_path_installation = False

    for path, permissions in required_dir_paths:
        if not Path(path).is_dir():
            if not system_path_installation:
                sys.exit(f"The directory {path} is missing; "
                         "you may need to (re-)run `cmt-install.py`; aborting.")
            result = secure_mkdir(directory=path, permissions=permissions, exist_ok=False)
            if result != [SecurityStatus.OK]:
                return result

    for path, permissions in required_dir_or_symlink_paths:
        if not Path(path).is_dir():
            if not system_path_installation and not Path(path).is_symlink():
                sys.exit(f"The symlink {path} is missing; "
                         "you may need to (re-)run `cmt-install.py`; aborting.")
            result = secure_mkdir(directory=path, permissions=permissions, exist_ok=False)
            if result != [SecurityStatus.OK]:
                return result
    return [SecurityStatus.OK]
