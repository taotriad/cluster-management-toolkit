# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Extract and return information about volumes from Ansible facts.
"""

import os
from typing import Any

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import disksize_to_human

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.listgetters.check_matchlist import check_matchlist
from clustermanagementtoolkit.listgetters.get_device_model import get_device_model


# pylint: disable-next=unused-argument
def listgetter_ansible_volumes(obj: dict, **kwargs: Any) -> tuple[list[dict[str, Any]], str]:
    """
    Given an Ansible facts dict for a host, return information about its volumes.

        Parameters:
            obj (dict): The object to extract data from
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of data
                (int): The status for the request
    """
    vlist: list[dict[str, Any]] = []

    # Find all mounts
    for item in deep_get(obj, DictPath("ansible_mounts"), []):
        d: dict[str, Any] = {}
        device = deep_get(item, DictPath("device"), "")
        if not device:
            continue
        fstype = deep_get(item, DictPath("fstype"), "")
        size_total = deep_get(item, DictPath("size_total"), 0)
        if not size_total:
            continue
        size_available = deep_get(item, DictPath("size_available"), 0)
        partition_size_total = disksize_to_human(size_total)
        partition_size_used = disksize_to_human(size_total - size_available)
        mountpoint = deep_get(item, DictPath("mount"), "")
        options = deep_get(item, DictPath("options"), "").split(",")
        # NFS mounts can be added directly; no need to do lookups
        if fstype == "nfs":
            d = {
                "mountpoint": mountpoint,
                "fstype": fstype,
                "options": options,
                "device": device,
                "model": "",
                "partition_size_used": partition_size_used,
                "partition_size_total": partition_size_total,
            }
            vlist.append(d)
            continue
        device = os.path.basename(device)

        if check_matchlist(mountpoint,
                           deep_get(cmtlib.cmtconfig,
                                    DictPath("__Inventory#mountpoint_skiplist"),
                                    ["/boot/efi",
                                     "/var/lib/origin/*",
                                     "/var/snap/*",
                                     "/run/*",
                                     "*@docker*"])):
            continue
        if check_matchlist(device,
                           deep_get(cmtlib.cmtconfig,
                                    DictPath("__Inventory#device_skiplist"),
                                    ["loop*"])):
            continue

        model = get_device_model(obj, device)
        d = {
            "mountpoint": mountpoint,
            "fstype": fstype,
            "options": options,
            "device": device,
            "partition_size_used": partition_size_used,
            "partition_size_total": partition_size_total,
            "model": model,
        }
        vlist.append(d)

    return vlist, "OK"
