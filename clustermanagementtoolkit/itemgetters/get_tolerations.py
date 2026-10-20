# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns a list of tolerations.
"""

from typing import Any, cast

from clustermanagementtoolkit.cmtlib import make_set_expression_list

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


def get_tolerations(obj: dict, **kwargs: Any) -> list[tuple[str, str, str, str, str]]:
    """
    Get a list of tolerations.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path ([str]): A list of paths (a path followed by its fallbacks) to get data from
        Returns:
            ([(str, str, str, str, str)]): A list of pod tolerations
                (str): key
                (str): operator
                (str): value
                (str): effect
                (str): timeout
    """
    path: list[DictPath] = deep_get(kwargs, DictPath("path"),
                                    [DictPath("spec#tolerations"),
                                     DictPath("scheduling#tolerations")])

    expression_list: list[dict[str, Any]] = deep_get_with_fallback(obj, path, [])
    return cast(list[tuple[str, str, str, str, str]],
                make_set_expression_list(expression_list,
                                         timeout_paths=[DictPath("tolerationSeconds")],
                                         is_toleration=True))
