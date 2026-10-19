# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import make_cel_expression
from clustermanagementtoolkit.cmtlib import make_label_selector
from clustermanagementtoolkit.cmtlib import make_set_expression


def get_selector_list(obj: dict, **kwargs: Any) -> list[list[str]]:
    """
    Format selectors from a list or dict of selectors.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the list or dict
        Returns:
            ([[str]]): A list of selector expressions
    """
    path: str = deep_get(kwargs, DictPath("path"))
    reparent: str = deep_get(kwargs, DictPath("reparent"))

    selectors: list[list[str]] = []

    tmp: dict | list = deep_get(obj, DictPath(path), {})
    if isinstance(tmp, dict):
        if reparent:
            tmp = [
                {
                    reparent: tmp,
                },
            ]
        else:
            tmp = [tmp]
    elif isinstance(tmp, str) and reparent == "matchLabels":
        tmp = [
            {
                reparent: cmtlib.split_match_label_selector(tmp),
            },
        ]

    for selector in tmp:
        if "cel" in selector:
            selectors.append([make_cel_expression([selector["cel"]])])
        if "matchExpressions" in selector:
            selectors.append([make_set_expression(selector["matchExpressions"])])
        if "matchFields" in selector:
            selectors.append([make_set_expression(selector["matchFields"])])
        if "matchLabels" in selector:
            selectors.append([make_label_selector(selector["matchLabels"])])
    return selectors
