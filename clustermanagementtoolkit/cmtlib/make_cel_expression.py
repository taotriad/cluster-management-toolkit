# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


# pylint: disable-next=unused-argument
def make_cel_expression(expression_list: list[dict], **kwargs: Any) -> str:
    """
    Join CEL expressions data into one single string.

        Parameters:
            expression_list (dict): The dict to extract the data from
        Returns:
            (str): The set expressions joined into one string
    """
    cel_expressions: list[str] = []

    if expression_list:
        for selector in expression_list:
            if (tmp := deep_get_with_fallback(selector,
                                              [DictPath("cel#expression"),
                                               DictPath("expression")], "")):
                cel_expressions.append(tmp)

    return ",".join(cel_expressions)
