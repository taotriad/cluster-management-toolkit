# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A generator for lists with status-highlighting.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit.generators.format_list import format_list


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def generator_list_with_status(obj: dict, field: str, fieldlen: int, pad: bool,
                               ralign: bool, selected: bool,
                               **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Generate a formatted list, mapping the items based on their status.
    FIXME: This implementation is really ugly.

        Parameters:
            obj (dict): The object to get data from
            field (str): The field in the object to get data from
            fieldlen (int): The length of the field
            pad (bool): Pad the string?
            ralign (bool): Should the text be right-aligned?
            selected (bool): Should the generated field be selected?
            **kwargs (dict[str, Any]): Keyword arguments
        Returns:
            ([ThemeRef | ThemeStr]): A formatted string
    """
    items: list[tuple[str, ...]] = deep_get(obj, DictPath(field))
    if isinstance(items, tuple):
        items = [items]

    # Well, this works:ish, but it is ugly beyond belief.
    # it would be solved so much better with a mapping that uses a secondary value.
    newitems = []
    kwargs["field_colors"] = [
        ThemeAttr("main", "status_done"),
        ThemeAttr("main", "status_ok"),
        ThemeAttr("main", "status_pending"),
        ThemeAttr("main", "status_warning"),
        ThemeAttr("main", "status_admin"),
        ThemeAttr("main", "status_not_ok"),
        ThemeAttr("main", "status_unknown"),
        ThemeAttr("main", "status_critical"),
        ThemeAttr("types", "generic")]
    kwargs["field_separators"] = [ThemeRef("separators", "no_pad", selected)]

    for item, status in items:
        if status == StatusGroup.DONE:
            newitems.append((item,))
        if status == StatusGroup.OK:
            newitems.append(("", item))
        elif status == StatusGroup.PENDING:
            newitems.append(("", "", item))
        elif status == StatusGroup.WARNING:
            newitems.append(("", "", "", item))
        elif status == StatusGroup.ADMIN:
            newitems.append(("", "", "", "", item))
        elif status == StatusGroup.NOT_OK:
            newitems.append(("", "", "", "", "", item))
        elif status == StatusGroup.UNKNOWN:
            newitems.append(("", "", "", "", "", "", item))
        elif status == StatusGroup.CRIT:
            newitems.append(("", "", "", "", "", "", "", item))
        elif status == StatusGroup.NEUTRAL:
            newitems.append(("", "", "", "", "", "", "", "", item))
        else:
            newitems.append(("", "", "", "", "", "", "", "", item))

    return format_list(newitems, fieldlen, pad, ralign=ralign, selected=selected, **kwargs)
