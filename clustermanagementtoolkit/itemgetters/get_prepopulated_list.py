# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns a prepopulated list.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit import kubernetes_helper


# pylint: disable-next=too-many-locals
def get_prepopulated_list(obj: dict, **kwargs: Any) -> list[dict]:
    """
    Get a prepopulated list of actions;
    this itemgetter can be used, for instance, to populate
    a list of actions that can be performed on an object.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                items ([Any]): The data to populate the list from
        Returns:
            ([dict]): A list of prepulated items
    """
    items = deep_get(kwargs, DictPath("items"), [])

    vlist: list[dict] = []

    for item in items:
        action = deep_get(item, DictPath("action"))
        action_call = deep_get(item, DictPath("action_call"))
        action_args = deep_get(item, DictPath("action_args"), {})
        kind = deep_get(action_args, DictPath("kind"))
        kind_path = deep_get(action_args, DictPath("kind_path"))
        kind = deep_get(obj, DictPath(kind_path), kind)
        api_family = deep_get(action_args, DictPath("api_family"), "")
        api_family_path = deep_get(action_args, DictPath("api_family_path"))
        api_family = deep_get(obj, DictPath(api_family_path), api_family)
        name_path = deep_get(action_args, DictPath("name_path"))
        name = deep_get(obj, DictPath(name_path))
        namespace_path = deep_get(action_args, DictPath("namespace_path"))
        namespace = deep_get(obj, DictPath(namespace_path), "")
        if kind:
            kind = kubernetes_helper.guess_kind((kind, api_family))
        tmp_columns = deep_get(item, DictPath("columns"), [])
        args = deep_get(action_args, DictPath("args"), {})

        columns: list = []

        # Where necessary do path lookups.
        for column in tmp_columns:
            if isinstance(column, list):
                column = deep_get_with_fallback(obj, column, "")
                tmp_column: list[str] = []
                if not isinstance(column, (list, tuple)):
                    column = [column]
                for val in column:
                    tmp_column.append(str(val))
                column = ",".join(tmp_column)
            columns.append(column)

        vlist.append({
            "fields": columns,
            "ref": {
                "action": action,
                "action_call": action_call,
                "action_args": {
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "args": args,
                },
            },
        })

    return vlist
