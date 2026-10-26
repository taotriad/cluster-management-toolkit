# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Join set expressions data into one single string usable in a label selector.
"""

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def make_label_selector_set_expression(expression_list: list[dict]) -> str:
    """
    Join set expressions data into one single string usable in a label selector.

        Parameters:
            expression_list (dict): The dict to extract the data from
        Returns:
            (str): The set expressions joined into one string
    """
    vlist: list[str] = []

    for d in expression_list:
        key = deep_get(d, DictPath("key"))
        operator = deep_get(d, DictPath("operator"))
        values = deep_get(d, DictPath("values"))
        vlist.append(f"{key} {operator.lower()} ({','.join(values)})")
    return ", ".join(vlist)
