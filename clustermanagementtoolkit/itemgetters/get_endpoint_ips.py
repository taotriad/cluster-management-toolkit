# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that returns a list of endpoint IPs.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_endpoint_ips(subsets: list[dict]) -> list[str]:
    """
    Get a list of endpoint IPs.
    Note: this is a helper, not an itemgetter.

        Parameters:
            subsets ([dict]): The subsets to get endpoint IPs from
        Returns:
            ([str]): A list of endpoint IPs
    """
    endpoints = []
    notready = 0

    if subsets is None:
        return ["<none>"]

    for subset in subsets:
        # Keep track of whether we have not ready addresses
        if (deep_get(subset, DictPath("notReadyAddresses")) is not None
                and deep_get(subset, DictPath("notReadyAddresses"))):
            notready += 1

        if deep_get(subset, DictPath("addresses")) is None:
            continue

        for address in deep_get(subset, DictPath("addresses"), []):
            endpoints.append(deep_get(address, DictPath("ip")))

    if not endpoints:
        if notready:
            return ["<not ready>"]
        return ["<none>"]

    return endpoints
