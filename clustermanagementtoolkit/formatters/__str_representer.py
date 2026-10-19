# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

import sys
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import yaml; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install PyYAML`; aborting.")


def __str_representer(dumper: yaml.Dumper, data: Any) -> yaml.Node:
    """
    Reformat yaml with |-style str.

        Parameters:
            dumper: Opaque type internal to python-yaml
            data: Opaque type internal to python-yaml
        Returns:
            (yaml.Node): Opaque type internal to python-yaml
    """
    if "\n" in data:  # pragma: no cover
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)  # pragma: no cover
