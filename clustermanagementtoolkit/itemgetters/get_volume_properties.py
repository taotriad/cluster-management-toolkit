# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns the properties for a Persistent Volume.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.itemgetters.get_pv_type import get_pv_type

from clustermanagementtoolkit.pvtypes import KNOWN_PV_TYPES


# pylint: disable-next=unused-argument
def get_volume_properties(obj: dict, **kwargs: Any) -> list[tuple[str, str]]:
    """
    Get the properties for a persistent volume.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([(str, str)]): A list of volume properties
    """
    volume_properties: list[tuple[str, str]] = []

    # First find out what kind of volume we are dealing with
    pv_type = get_pv_type(obj)
    if pv_type is None:
        return volume_properties

    properties = deep_get(KNOWN_PV_TYPES, DictPath(f"{pv_type}#properties"), {})
    for key in properties:
        default = deep_get(properties, DictPath(f"{key}#default"), "")
        path = deep_get(properties, DictPath(f"{key}#path"), "")
        value = deep_get(obj, DictPath(f"spec#{pv_type}#{path}"), default)
        if isinstance(value, list):
            value = ",".join(value)
        elif isinstance(value, dict):
            value = ",".join(f"{key}:{val}" for (key, val) in value.items())
        # We do not need to check for bool, since it is a subclass of int
        elif isinstance(value, (int, float, str)):
            value = str(value)
        else:
            raise TypeError(f"Unhandled type {type(value)} for {key}={value}")
        volume_properties.append((key, value))

    return volume_properties
