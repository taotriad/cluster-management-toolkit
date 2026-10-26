# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that returns the type of a Persistent Volume.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.pvtypes import KNOWN_PV_TYPES


def get_pv_type(obj: dict) -> str | None:
    """
    Given a volume object, return its type.
    Note: this is a helper, not an itemgetter.

        Parameters:
            obj (dict): The object to get data from
        Returns:
            (str): The volume type
    """
    for pv_type in KNOWN_PV_TYPES:
        if pv_type in deep_get(obj, DictPath("spec"), {}):
            return pv_type
    return None
