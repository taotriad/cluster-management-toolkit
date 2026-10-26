# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Formatter for lists.
"""
from collections.abc import Callable
from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_select

from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
from clustermanagementtoolkit.generators.format_special import format_special
from clustermanagementtoolkit.generators.map_value import map_value
from clustermanagementtoolkit.generators.generators_types import FormattingType


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def format_list(items: Any, fieldlen: int, pad: bool, **kwargs: Any) -> list[ThemeRef | ThemeStr]:
    """
    Format the elements of a list.

        Parameters:
            items (Any): The list items
            fieldlen (int): The length of the field
            pad (bool): Pad the string? to insert after the field
            **kwargs (dict[str, Any]): Keyword arguments
                ralign (bool): Align the data to the right?
                selected (bool): Mark the field as selected?
                item_separator (ThemeRef): The separator between each item
                field_separators ([ThemeRef]): The separators between each field
                ellipsise (int): Ellipsise after this many elements (-1 == disabled)
                ellipsis (ThemeRef): The marker to use when ellipsising the list
                field_prefixes ([[ThemeRef]]): Prefixes for each element
                field_suffixes ([[ThemeRef]]): Suffixes for each element
                mapping (dict): Mappings passed to map_value()
                field_formatters (list[Callable]): A list of field formatters
        Returns:
            (ThemeArray): The formatted themearray
    """
    ralign: bool = deep_get(kwargs, DictPath("ralign"), False)
    selected: bool = deep_get(kwargs, DictPath("selected"), False)
    item_separator: ThemeRef = deep_get(kwargs, DictPath("item_separator"),
                                        ThemeRef("separators", "list", selected))
    field_separators: list[ThemeRef] = deep_get(kwargs, DictPath("field_separators"),
                                                [ThemeRef("separators", "field", selected)])
    field_colors: list[ThemeAttr] = deep_get(kwargs, DictPath("field_colors"),
                                             [ThemeAttr("types", "field")])
    ellipsise: int = deep_get(kwargs, DictPath("ellipsise"), -1)
    ellipsis: ThemeRef = deep_get(kwargs, DictPath("ellipsis"),
                                  ThemeRef("separators", "ellipsis", selected))
    field_prefixes: list[list[ThemeRef]] = deep_get(kwargs, DictPath("field_prefixes"))
    field_suffixes: list[list[ThemeRef]] = deep_get(kwargs, DictPath("field_suffixes"))
    mapping: dict = deep_get(kwargs, DictPath("mapping"), {})
    collate: int = deep_get(kwargs, DictPath("args#collate"), 1)
    field_formatters: list[Callable | None] = \
        deep_get(kwargs, DictPath("field_formatters"), [])

    array: list[ThemeRef | ThemeStr] = []

    if not isinstance(field_separators, list):
        raise TypeError("field_separators should be a list of ThemeRef, "
                        f"not a single tuple; {field_separators}")

    if not isinstance(field_colors, list):
        raise TypeError("field_colors should be a list of ThemeAttr, "
                        f"not a single tuple; {field_colors}")

    if not isinstance(items, list):
        items = [items]

    if collate > 1 and isinstance(items, list):
        if items and isinstance(items[0], tuple):
            tmpitems: Any = items[0]
        else:
            tmpitems = items
        newitems = []
        itemgroup = []
        for i, item in enumerate(tmpitems):
            itemgroup.append(item)
            if i % collate == collate - 1:
                newitems.append(tuple(itemgroup))
                itemgroup = []
        if itemgroup and len(itemgroup) < collate:
            itemgroup.extend([None] * (collate - len(itemgroup)))
        if itemgroup:
            newitems.append(tuple(itemgroup))
        items = newitems

    elcount = 0
    skip_separator = True

    for item in items:
        if array:
            item_sep = item_separator
            item_sep.selected = selected
            array.append(item_sep)
            elcount += 1

        if elcount == ellipsise:
            ell = ellipsis
            ell.selected = selected
            array.append(ellipsis)
            break

        # Treat all types as tuples no matter if they are;
        # since tuples consist of 2+ elements we add None.
        if not isinstance(item, tuple):
            item = (item, None)

        # If we're collating and using a ranges-mapping and the tuple is 2 entries long
        # we're trying to do a comparison.
        if collate and "ranges" in mapping and len(item) == 2:
            formatted_string, __string = map_value(item, selected=selected, mapping=mapping)
            # OK, we know now that we will be appending the field, so do the prefix
            if field_prefixes:
                array += themearray_select(field_prefixes[0], selected=selected, force=True)
            array.append(formatted_string)
            # And now the suffix
            if field_suffixes:
                array += themearray_select(field_suffixes[0], selected=selected, force=True)
            continue

        for i, data in enumerate(item):
            if data is None:
                continue

            string = str(data)

            if not string:
                continue

            if i and not skip_separator:
                field_sep = field_separators[min(i - 1, len(field_separators) - 1)]
                field_sep.selected = selected
                array.append(field_sep)

            field_formatter: Callable | None = None
            field_formatting: FormattingType = {
                "item_separator": deep_get(kwargs, DictPath("item_separator")),
                "field_separators": deep_get(kwargs, DictPath("field_separators")),
                "field_colors": deep_get(kwargs, DictPath("field_colors")),
                "ellipsise": deep_get(kwargs, DictPath("ellipsise"), -1),
                "ellipsis": deep_get(kwargs, DictPath("ellipsis")),
                "field_prefixes": deep_get(kwargs, DictPath("field_prefixes")),
                "field_suffixes": deep_get(kwargs, DictPath("field_suffixes")),
            }

            if field_formatters:
                field_formatter = field_formatters[min(i, len(field_formatters) - 1)]
            if (tmp := format_special(string, selected)) is not None:
                formatted_string = tmp
            elif field_formatter:
                formatted_string = field_formatter(string, selected, ftype="numerical",
                                                   formatting=field_formatting)
            else:
                default_field_color = field_colors[min(i, len(field_colors) - 1)]
                formatted_string, __string = map_value(string, selected=selected,
                                                       default_field_color=default_field_color,
                                                       mapping=mapping, mapitems=items)

            # OK, we know now that we will be appending the field, so do the prefix
            if field_prefixes is not None and i < len(field_prefixes):
                array += themearray_select(field_prefixes[i], selected=selected, force=True)
            if isinstance(formatted_string, list):
                array += formatted_string
            else:
                array.append(formatted_string)
            # And now the suffix
            if field_suffixes is not None and i < len(field_suffixes):
                array += themearray_select(field_suffixes[i], selected=selected, force=True)
            skip_separator = False

    return align_and_pad(array, fieldlen=fieldlen, pad=pad, ralign=ralign, selected=selected)
