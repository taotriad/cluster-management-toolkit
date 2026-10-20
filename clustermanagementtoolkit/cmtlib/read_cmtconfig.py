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
import sys

from clustermanagementtoolkit.cmtpaths import (
    CMT_CONFIG_FILE,
    CMT_CONFIG_FILE_DIR,
    SYSTEM_CMT_CONFIG_FILE,
    SYSTEM_CMT_CONFIG_FILE_DIR,
)

from clustermanagementtoolkit.cmttypes import FilePath


# pylint: disable-next=too-many-branches
def read_cmtconfig() -> dict:
    """
    Read cmt.yaml and cmt.yaml.d/*.yaml and update the global cmtconfig dict.

        Returns:
            (dict): A reference to the global cmtconfig dict
    """
    try:
        # This is for the benefit of avoiding dependency cycles
        # pylint: disable-next=import-outside-toplevel
        from natsort import natsorted
    except ModuleNotFoundError:  # pragma: no cover
        sys.exit("ModuleNotFoundError: Could not import natsort; "
                 "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

    # Start with an empty base configuration
    local_cmtconfig = {}

    # This is to allow use of ansithemeprint from cmt-install.py.
    # pylint: disable-next=import-outside-toplevel
    from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

    if Path(SYSTEM_CMT_CONFIG_FILE).is_file():
        # Read the base configuration file from /etc (if available)
        tmp_cmtconfig = secure_read_yaml(SYSTEM_CMT_CONFIG_FILE)
        if tmp_cmtconfig is not None:
            local_cmtconfig = dict(tmp_cmtconfig)
    elif Path(CMT_CONFIG_FILE).is_file():
        # Read the base configuration file from /home/.cmt (if available)
        tmp_cmtconfig = secure_read_yaml(CMT_CONFIG_FILE)
        if tmp_cmtconfig is not None:
            local_cmtconfig = dict(tmp_cmtconfig)

    # Now read /etc/cmt.yaml.d/*
    system_config_dir = Path(SYSTEM_CMT_CONFIG_FILE_DIR)
    if system_config_dir.is_dir():
        for path in natsorted(system_config_dir.iterdir()):
            filename = path.name

            # Skip tempfiles and only read entries that end with .y{,a}ml
            if filename.startswith(("~", ".")) or not filename.endswith((".yaml", ".yml")):
                continue

            # Read the conflet files
            morecmtconfig = secure_read_yaml(FilePath(path))

            # Handle config files without any values defined
            if morecmtconfig is not None:
                local_cmtconfig = {**local_cmtconfig, **dict(morecmtconfig)}

    # Finally {HOMEDIR}/cmt.yaml.d/*
    config_dir = Path(CMT_CONFIG_FILE_DIR)
    if config_dir.is_dir():
        for path in natsorted(Path(CMT_CONFIG_FILE_DIR).iterdir()):
            filename = path.name

            # Skip tempfiles and only read entries that end with .y{,a}ml
            if filename.startswith(("~", ".")) or not filename.endswith((".yaml", ".yml")):
                continue

            # Read the conflet files
            morecmtconfig = secure_read_yaml(FilePath(path))

            # Handle config files without any values defined
            if morecmtconfig is not None:
                local_cmtconfig = {**local_cmtconfig, **dict(morecmtconfig)}

    return copy.deepcopy(local_cmtconfig)
