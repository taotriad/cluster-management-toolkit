# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns package versions.
"""

from typing import Any

from clustermanagementtoolkit.cmtlib import get_package_versions

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_package_version_list(obj: dict, **kwargs: Any) -> list[tuple[str, str]] | None:
    """
    Get the package version list.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                name (str): The name of the node
                name_path (str): The path to the name of the node
        Returns:
            ([(str, str)]): A list of package versions
    """
    name_path = deep_get(kwargs, DictPath("name_path"), "")
    hostname = deep_get(obj, DictPath(name_path))
    hostname = deep_get(kwargs, DictPath("name"), hostname)
    try:
        package_versions = get_package_versions(hostname)
    except ValueError:
        package_versions = None
    return package_versions
