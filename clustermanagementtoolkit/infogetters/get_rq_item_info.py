# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_rq_item_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Resource Quotas.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _obj (dict): The dict to extract data from
                hard_path (str): Path to the hard quota
                used_path (str): Path to the used hard quota
        Returns:
            info ([dict]): A list with info
    """
    obj = deep_get(kwargs, DictPath("_obj"))
    hard_path = deep_get(kwargs, DictPath("hard_path"), DictPath("spec#hard"))
    used_path = deep_get(kwargs, DictPath("used_path"), DictPath("status#used#hard"))
    info = []

    if obj is None:
        return []

    for resource in deep_get(obj, hard_path, []):
        used = deep_get(obj, DictPath(f"{used_path}#{resource}"), 0)
        hard = deep_get(obj, DictPath(f"{hard_path}#{resource}"), 0)

        info.append({
            "resource": resource,
            "used": used,
            "hard": hard,
        })
    return info
