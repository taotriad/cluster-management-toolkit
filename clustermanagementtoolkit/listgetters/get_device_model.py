# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the device model for a partition.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_device_model(obj: dict, device: DictPath) -> str:
    """
    Return the device model for a partition.

        Parameters:
            obj (dict): The object to extract device model information from
            device (DictPath): The device to extract model information for
        Returns:
            (str): The device model
    """
    for dev in deep_get(obj, DictPath("ansible_devices"), {}):
        partitions = deep_get(obj, DictPath(f"ansible_devices#{dev}#partitions"), {})
        model = deep_get(obj, DictPath(f"ansible_devices#{dev}#model"), "")
        for partition in partitions:
            if device in partition:
                return model
    return ""
