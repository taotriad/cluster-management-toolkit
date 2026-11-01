# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format a Kubernetes toleration.
"""
from typing import Any, cast

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_select


# pylint: disable-next=too-many-branches
def format_toleration(items: dict | list[dict],
                      selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a list of tolerations, return them formatted.

        Parameters:
            items (dict|[dict]): The dict to format
            selected (bool): Should the output be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
                item_separator (ThemeRef): The separator between each element in the list
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    array: list[ThemeRef | ThemeStr] = []

    item_separator: ThemeRef = deep_get(kwargs, DictPath("item_separator"),
                                        ThemeRef("separators", "list"))

    if isinstance(items, dict):
        items = [items]

    for toleration in items:
        _vlist: list[ThemeRef | ThemeStr] = []
        key = deep_get(toleration, DictPath("key"), "")
        operator = deep_get(toleration, DictPath("operator"), "")
        values = deep_get(toleration, DictPath("values"), "")
        effect = deep_get(toleration, DictPath("effect"), "")
        # Should we include this?
        # toleration_seconds = deep_get(toleration, DictPath("tolerationSeconds"), -1)
        if _vlist:
            _vlist.append(item_separator)
        values_joined: list[ThemeRef | ThemeStr] = []
        for value in values:
            if values_joined:
                values_joined.append(item_separator)
            if isinstance(value, (int, float)):
                valueattr = ThemeAttr("types", "numerical")
            else:
                valueattr = ThemeAttr("types", "generic")
            if isinstance(value, (int, float)):
                values_joined.append(ThemeStr(str(value), valueattr))
            else:
                values_joined.append(ThemeStr(str(value), valueattr))
        if values_joined:
            values_joined = [
                ThemeRef("separators", "space"),
                ThemeRef("separators", "list_start"),
            ] + values_joined + [
                ThemeRef("separators", "list_end"),
            ]

        effect_array: list[ThemeRef | ThemeStr] = []
        if effect:
            effect_array = [
                ThemeRef("separators", "keyvalue"),
                ThemeStr(f"{effect}", ThemeAttr("types", "effect")),
            ]

        _vlist += [
            ThemeStr(f"{key}", ThemeAttr("types", "key")),
            ThemeRef("separators", "space"),
            ThemeStr(f"{operator}", ThemeAttr("types", "operator")),
        ]
        _vlist += values_joined
        _vlist += effect_array

        if array and _vlist:
            array.append(item_separator)
        # This doesn't need to be conditional, since it'll be a no-op if _vlist is empty.
        array += _vlist

    if not array:
        array = [
            ThemeStr("", ThemeAttr("types", "generic"))
        ]

    return cast(list, themearray_select(array, selected=selected, force=True))
