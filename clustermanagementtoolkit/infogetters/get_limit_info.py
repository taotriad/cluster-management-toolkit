# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_limit_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Limits.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([dict]): A list with info
    """
    obj = deep_get(kwargs, DictPath("_obj"))
    info: list[dict] = []

    if obj is None:
        return []

    for limit in deep_get(obj, DictPath("spec#limits"), []):
        resources = set()

        for item in deep_get(limit, DictPath("default"), []):
            resources.add(item)
        for item in deep_get(limit, DictPath("defaultRequest"), []):
            resources.add(item)
        for item in deep_get(limit, DictPath("min"), []):
            resources.add(item)
        for item in deep_get(limit, DictPath("max"), []):
            resources.add(item)
        for item in deep_get(limit, DictPath("max"), []):
            resources.add(item)
        for item in deep_get(limit, DictPath("maxLimitRequestRatio"), []):
            resources.add(item)
        ltype = deep_get(limit, DictPath("type"))

        for item in resources:
            lmin = deep_get(limit, DictPath(f"min#{item}"), "-")
            lmax = deep_get(limit, DictPath(f"max#{item}"), "-")
            default_request = deep_get(limit, DictPath(f"defaultRequest#{item}"), "-")
            default_limit = deep_get(limit, DictPath(f"default#{item}"), "-")
            max_lr_ratio = deep_get(limit, DictPath(f"maxLimitRequestRatio#{item}"), "-")
            info.append({
                "name": item,
                "ref": limit,
                "ltype": ltype,
                "lmin": lmin,
                "lmax": lmax,
                "default_request": default_request,
                "default_limit": default_limit,
                "max_lr_ratio": max_lr_ratio,
            })
    return info
