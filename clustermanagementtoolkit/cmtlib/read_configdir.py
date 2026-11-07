# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Read a configuration file in <config>.d/*.yaml format.
"""

import copy
from pathlib import Path
from typing import Any

from clustermanagementtoolkit.cmttypes import FilePath


def read_configdir(configpath: Path) -> dict:
    """
    Read a configuration file in <config>.d/*.yaml format.

        Parameters:
            configpath (FilePath): The path to the config directory
        Returns:
            (dict): A dictionary with the configuration
    """
    # This is for the benefit of avoiding dependency cycles.
    # pylint: disable-next=import-outside-toplevel
    from natsort import natsorted

    # Start with an empty base configuration.
    config: dict[str, Any] = {}

    # This is to allow use of ansithemeprint from cmt-install.py.
    # pylint: disable-next=import-outside-toplevel
    from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

    # Read <config>.d/*.
    if configpath.is_dir():
        for path in natsorted(configpath.iterdir()):
            filename = path.name

            # Skip tempfiles and only read entries that end with .y{,a}ml.
            if filename.startswith(("~", ".")) or not filename.endswith((".yaml", ".yml")):
                continue

            # Read the conflet files.
            if (more_config := secure_read_yaml(FilePath(path))) is not None:
                config = {**config, **dict(more_config)}

    return copy.deepcopy(config)
