# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return an object created from a journalctl log message.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def objgetter_journalctl_log(obj: list[dict]) -> dict:
    """
    Format a journalctl log message.

        Parameters:
            obj ([dict]): The obj to get data from
        Returns:
            (dict): A journalctl facts object
    """
    data = {
        # This should only be logs from one host, so we can get the hostname
        "name": deep_get(obj[0], DictPath("name")),
        "host": deep_get(obj[0], DictPath("host")),
        "created_at": deep_get(obj[0], DictPath("created_at")),
        "obj": obj,
    }
    return data
