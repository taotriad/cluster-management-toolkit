# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError


# pylint: disable-next=too-many-locals,too-many-branches
def get_subsets_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Endpoint subsets.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _obj (dict): The dict to extract data from
        Returns:
            ([dict]): A list with info
    """
    if (obj := deep_get(kwargs, DictPath("_obj"))) is None:
        return []

    subsets_ = []
    subsets = []

    # Policy for subsets expansion
    expand_subsets = deep_get(cmtlib.cmtconfig, DictPath("Endpoints#expand_subsets"), "None")
    if expand_subsets not in ("None", "Port", "Address", "Both"):
        expand_subsets = "None"

    for subset in deep_get(obj, DictPath("subsets"), []):
        ready_addresses = []
        not_ready_addresses = []
        ports = []

        if deep_get(subset, DictPath("ports")) is None:
            continue

        if not deep_get(subset, DictPath("addresses"), []) \
                and not deep_get(subset, DictPath("notReadyAddresses"), []):
            continue

        for port in deep_get(subset, DictPath("ports"), []):
            name = deep_get(port, DictPath("name"), "")
            ports.append((name,
                          deep_get(port, DictPath("port")),
                          deep_get(port, DictPath("protocol"))))

        for address in deep_get(subset, DictPath("addresses"), []):
            ready_addresses.append(deep_get(address, DictPath("ip")))

        for not_ready_address in deep_get(subset, DictPath("notReadyAddresses"), []):
            not_ready_addresses.append(deep_get(not_ready_address, DictPath("ip")))

        if expand_subsets == "None":
            if ready_addresses:
                subsets.append((ready_addresses, ports, "Ready", StatusGroup.OK))
            if not_ready_addresses:
                subsets.append((not_ready_addresses, ports, "Not Ready", StatusGroup.NOT_OK))
        elif expand_subsets == "Port":
            for port in ports:
                if ready_addresses:
                    subsets.append((ready_addresses, [port], "Ready", StatusGroup.OK))
                if not_ready_addresses:
                    subsets.append((not_ready_addresses, [port], "Not Ready", StatusGroup.NOT_OK))
        elif expand_subsets == "Address":
            for address in ready_addresses:
                subsets.append(([address], ports, "Ready", StatusGroup.OK))
            for address in not_ready_addresses:
                subsets.append(([address], ports, "Not Ready", StatusGroup.NOT_OK))
        elif expand_subsets == "Both":
            for port in ports:
                for address in ready_addresses:
                    subsets.append(([address], [port], "Ready", StatusGroup.OK))
                for address in not_ready_addresses:
                    subsets.append(([address], [port], "Not Ready", StatusGroup.NOT_OK))
        else:  # pragma: nocover
            raise ProgrammingError("get_subsets_info() got expand_subsets={expand_subsets}; "
                                   "this shouldn't be possible")

    for addresses, ports, status, status_group in subsets:
        subsets_.append({
            "addresses": addresses,
            "ports": ports,
            "status": status,
            "status_group": status_group,
        })
    return subsets_
