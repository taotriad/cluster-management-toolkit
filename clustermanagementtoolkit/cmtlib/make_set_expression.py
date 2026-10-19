# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import cast

from clustermanagementtoolkit.cmtlib.make_set_expression_list import make_set_expression_list


def make_set_expression(expression_list: list[dict]) -> str:
    """
    Join set expressions data into one single string.

        Parameters:
            expression_list (dict): The dict to extract the data from
        Returns:
            (str): The set expressions joined into one string
    """
    vlist: list[tuple[str, str, str]] = \
        cast(list[tuple[str, str, str]], make_set_expression_list(expression_list))
    xlist = []
    for key, operator, values in vlist:
        xlist.append(f"{key} {operator}{values}")
    return ", ".join(xlist)
