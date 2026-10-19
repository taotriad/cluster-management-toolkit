# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format a Kubernetes selector.
"""
from typing import Any, cast

from clustermanagementtoolkit.cmtlib import split_match_label_selector

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_select

from clustermanagementtoolkit import formatters


# pylint: disable-next=too-many-branches,too-many-locals,too-many-statements
def format_selector(items: dict | list[dict],
                    selected: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Given a list of selectors, return them formatted as selectors.

        Parameters:
            items (dict|[dict]): The strings to format
            selected (bool): Should the strings be treated as selected?
            **kwargs (dict[str, Any]): Keyword arguments
                item_separator (ThemeRef): The separator between each element in the list
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    string_selector_type: str = deep_get(kwargs, DictPath("args#selector#type"), "matchLabels")

    array: list[ThemeRef | ThemeStr] = []

    if not isinstance(items, (list, tuple)):
        if isinstance(items, str):
            if string_selector_type == "matchLabels":
                try:
                    formatted = split_match_label_selector(items)
                    items = {
                        "matchLabels": formatted,
                    }
                except ValueError:
                    array = [
                        ThemeStr(f"{items}", ThemeAttr("types", "generic"))
                    ]
                    items = []
            elif string_selector_type == "cel":
                items = {
                    "cel": {
                        "expression": items,
                    },
                }
        if items:
            items = [items]

    item_separator: ThemeRef = deep_get(kwargs, DictPath("item_separator"),
                                        ThemeRef("separators", "list"))

    # pylint: disable-next=too-many-nested-blocks
    for selectors in items:
        # The same selector probably shouldn't contain multiple types in one item,
        # but just in case they do we handle it.
        for selector_type, selector in selectors.items():
            _vlist: list[ThemeRef | ThemeStr] = []
            if selector_type == "cel":
                tmp = formatters.format_cel(deep_get(selector, DictPath("expression"), ""))
                if tmp:
                    if _vlist:
                        _vlist.append(item_separator)
                    _vlist += tmp[0]
            elif selector_type == "matchExpressions":
                for expression in selector:
                    key = deep_get(expression, DictPath("key"), "")
                    operator = deep_get(expression, DictPath("operator"), "")
                    values = deep_get(expression, DictPath("values"), "")
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

                    _vlist += [
                        ThemeStr(f"{key}", ThemeAttr("types", "key")),
                        ThemeRef("separators", "space"),
                        ThemeStr(f"{operator}", ThemeAttr("types", "operator")),
                    ]
                    _vlist += values_joined
            elif selector_type == "matchFields":
                raise NotImplementedError("format_selector() does not support matchFields yet")
            elif selector_type == "matchLabels":
                for key, value in selector.items():
                    if _vlist:
                        _vlist.append(item_separator)
                    try:
                        # float() is useful here since it accepts both int and float.
                        # Should we perhaps format float using numerical with units?
                        if isinstance(value, (int, float)) or float(value):
                            valueattr = ThemeAttr("types", "numerical")
                        else:
                            valueattr = ThemeAttr("types", "generic")
                    except ValueError:
                        valueattr = ThemeAttr("types", "generic")

                    _vlist += [
                        ThemeStr(f"{key}", ThemeAttr("types", "key")),
                        ThemeRef("separators", "keyvalue"),
                        ThemeStr(f"{value}", valueattr),
                    ]

            if array and _vlist:
                array.append(item_separator)
            # This doesn't need to be conditional, since it'll be a no-op if _vlist is empty.
            array += _vlist

    if not array:
        array = [
            ThemeStr("", ThemeAttr("types", "generic"))
        ]

    return cast(list, themearray_select(array, selected=selected, force=True))
