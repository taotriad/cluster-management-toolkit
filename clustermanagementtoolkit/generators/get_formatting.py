# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a formatting dict.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# The return type of the formatting will be the same
# as the type of the default, so default == None is a programming error
# pylint: disable-next=too-many-branches
def get_formatting(field: dict[str, Any], formatting: str,
                   default: dict[str, Any]) -> list[ThemeAttr | ThemeStr | ThemeRef] | ThemeRef:
    """
    Given a field dict, the formatting we want to extract, and the default value to return
    if there's no suitable formatting, extract the formatting.

        Parameters:
            field (dict): The field dict to extract formatting from
            formatting (str): The name of the formatting to extract
            default (dict): The default formatting to return if no field-specific formatting
                            is available
    """
    result: list[ThemeAttr | ThemeStr | ThemeRef] = []
    items: dict | list[dict] = deep_get(field, DictPath(f"formatting#{formatting}"))

    if items is None:
        return deep_get(default, DictPath(f"{formatting}"))

    if not isinstance(items, (dict, list)):
        raise TypeError("Formatting must be either "
                        "list[dict | ThemeAttr | ThemeRef | ThemeStr] or list[list[dict]]; "
                        f"is type: {type(items)}")

    if default is None:
        raise ValueError(f"default cannot be None for field {field}, "
                         f"formatting {formatting}; this is a programming error")

    if len(items) < 1:
        raise ValueError(f"field {field}, formatting {formatting}: format list item is empty; "
                         "this is likely an error in the view file")

    default_context = None
    if formatting in ("item_separator", "field_separators",
                      "ellipsis", "field_prefixes", "field_suffixes"):
        default_context = "separators"
    elif formatting == "field_colors":
        default_context = "types"

    if isinstance(items, dict):
        context = deep_get(items, DictPath("context"), default_context)
        key = deep_get(items, DictPath("type"))
        return ThemeRef(context, key)

    for item in items:
        # field_prefixes/suffixes can be either list[ThemeRef | ThemeStr],
        # list[list[ThemeRef | ThemeStr]],
        # or ThemeRef | ThemeStr; in the latter case turn it into a list
        if isinstance(item, (ThemeAttr, ThemeRef, ThemeStr)):
            result.append(item)
        elif isinstance(item, list):
            new_item = []
            for subitem in item:
                context = deep_get(subitem, DictPath("context"), default_context)
                key = deep_get(subitem, DictPath("type"))
                new_item.append(ThemeRef(context, key, selected=None))
            result.append(new_item)
        elif isinstance(item, dict):
            context = deep_get(item, DictPath("context"), default_context)
            key = deep_get(item, DictPath("type"))
            if formatting in ("field_separators", "ellipsis"):
                result.append(ThemeRef(context, key))
            elif formatting == "field_colors":
                result.append(ThemeAttr(context, key))
            else:
                raise TypeError(f"Unknown formatting type {formatting}")
        else:
            raise TypeError(f"Formatting is of invalid type {type(item)}")

    return result
