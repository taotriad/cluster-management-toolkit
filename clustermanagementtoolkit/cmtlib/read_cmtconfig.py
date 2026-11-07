# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Read the configuration-file for CMT.
"""

import copy
from pathlib import Path
from typing import Any

from clustermanagementtoolkit.cmtpaths import (
    CMT_CONFIG_FILE,
    CMT_CONFIG_FILE_DIR,
    SYSTEM_CMT_CONFIG_FILE,
    SYSTEM_CMT_CONFIG_FILE_DIR,
)

from clustermanagementtoolkit.cmtlib.read_configdir import read_configdir


def read_cmtconfig() -> dict:
    """
    Read cmt.yaml and cmt.yaml.d/*.yaml and update the global cmtconfig dict.

        Returns:
            (dict): A reference to the global cmtconfig dict
    """
    # Start with an empty base configuration.
    local_cmtconfig: dict[str, Any] = {}

    # This is to allow use of ansithemeprint from cmt-install.py.
    # pylint: disable-next=import-outside-toplevel
    from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

    if Path(SYSTEM_CMT_CONFIG_FILE).is_file():
        # Read the base configuration file from /etc (if available).
        tmp_cmtconfig = secure_read_yaml(SYSTEM_CMT_CONFIG_FILE)
        if tmp_cmtconfig is not None:
            local_cmtconfig = dict(tmp_cmtconfig)
    elif Path(CMT_CONFIG_FILE).is_file():
        # Read the base configuration file from /home/.cmt (if available).
        tmp_cmtconfig = secure_read_yaml(CMT_CONFIG_FILE)
        if tmp_cmtconfig is not None:
            local_cmtconfig = dict(tmp_cmtconfig)

    # Now read /etc/cmt.yaml.d/*.
    system_config_dir = Path(SYSTEM_CMT_CONFIG_FILE_DIR)
    morecmtconfig = read_configdir(system_config_dir)
    local_cmtconfig = {**local_cmtconfig, **dict(morecmtconfig)}

    # Finally {HOMEDIR}/cmt.yaml.d/*.
    config_dir = Path(CMT_CONFIG_FILE_DIR)
    morecmtconfig = read_configdir(config_dir)
    local_cmtconfig = {**local_cmtconfig, **dict(morecmtconfig)}

    return copy.deepcopy(local_cmtconfig)
