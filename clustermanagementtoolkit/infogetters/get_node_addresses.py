# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that returns a list of internal/external IPs and hostnames.
"""

from clustermanagementtoolkit import about

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get


def get_node_addresses(addresses: list[dict]) -> tuple[str, list[str], list[str]]:
    """
    Given the addresses list return all internal/external IPs and the hostname.

        Parameters:
            addresses ([dict]): A list of address objects
        Returns:
            ((str, [str], [str])):
                (str): Hostname
                ([str]): Internal IPs
                ([str]): External IPs
    """
    iips = []
    eips = []

    new_name = None

    for address in addresses:
        address_type = deep_get(address, DictPath("type"))
        address_address = deep_get(address, DictPath("address"))
        if address_type == "InternalIP":
            iips.append(address_address)
        elif address_type == "ExternalIP":
            eips.append(address_address)
        # handle external IPs too
        elif address_type == "Hostname":
            if new_name is None:
                new_name = address_address
            else:
                msg = [
                    [("A host was encountered with multiple hostnames; ", "default"),
                     (f"{about.UI_PROGRAM_NAME}", "programname"),
                     (" currently only supports single hostnames.", "default")],
                    [("Please file a bugreport and include a YAML or JSON-dump for the node ",
                      "default"),
                     (f"{new_name}", "hostname"),
                     (".", "default")],
                ]
                unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(msg)
                cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
        else:
            continue

    if not iips:
        iips = ["<unset>"]
        eips = ["<unset>"]
    if not eips:
        eips = ["<none>"]
    if new_name is None:
        new_name = "<unset>"

    return new_name, iips, eips
