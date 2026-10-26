# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return remaining formatting information based on formatter.
"""

from typing import cast
import yaml

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import get_theme_ref

from clustermanagementtoolkit.generators.field_formatter_allowlist import field_formatter_allowlist
from clustermanagementtoolkit.generators.formatter_to_generator import formatter_to_generator
from clustermanagementtoolkit.generators.generator_basic import generator_basic
from clustermanagementtoolkit.generators.get_formatting import get_formatting


# This generates old-style fields from new-style fields
# pylint: disable-next=too-many-locals
def get_formatter(field: dict) -> dict:
    """
    Based on formatter, generator, etc and data type,
    figure out what the rest of the fields need to be.
    For instance, given only formatter this function will
    return also the generator.

        Parameters:
            field (dict): The field to complete
        Returns:
            (dict): A dict with new formatting information
    """
    tmp_field = {}

    formatter = deep_get(field, DictPath("formatter"))
    generator = deep_get(field, DictPath("generator"), generator_basic)

    field_separators_default = [ThemeRef("separators", "field")]

    if formatter is not None:
        if formatter not in formatter_to_generator:
            msg = [
                [("get_formatter()", "emphasis"),
                 (" called with invalid argument(s):", "error")],
                [("field=", "default"),
                 (yaml.dump(field), "argument"),
                 (" has an invalid ", "default"),
                 ("formatter", "argument")]
            ]

            unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(msg)

            raise ProgrammingError(unformatted_msg,
                                   severity=LogLevel.ERR,
                                   formatted_msg=formatted_msg)

        generator = deep_get(formatter_to_generator,
                             DictPath(f"{formatter}#generator"))
        field_separators_default = deep_get(formatter_to_generator,
                                            DictPath(f"{formatter}#field_separators_default"),
                                            field_separators_default)

    theme = get_theme_ref()
    if deep_get(field, DictPath("formatting#field_colors")) is None:
        if "type" in field and field["type"] in theme["types"]:
            field_colors: list[ThemeAttr] = [ThemeAttr("types", deep_get(field, DictPath("type")))]
        else:
            field_colors = cast(list[ThemeAttr],
                                get_formatting(field, "field_colors",
                                               {"field_colors": [ThemeAttr("types", "field")]}))
    else:
        field_colors = cast(list[ThemeAttr],
                            get_formatting(field, "field_colors",
                                           {"field_colors": [ThemeAttr("types", "field")]}))

    formatter_args = deep_get(field, DictPath("formatting#args"), {})
    field_prefixes = get_formatting(field, "field_prefixes", {"field_prefixes": []})
    field_suffixes = get_formatting(field, "field_suffixes", {"field_suffixes": []})
    field_separators = get_formatting(field, "field_separators",
                                      {"field_separators": field_separators_default})
    ellipsise = deep_get(field, DictPath("formatting#ellipsise"), -1)
    ellipsis = get_formatting(field, "ellipsis", {"ellipsis": ThemeRef("separators", "ellipsis")})
    item_separator = get_formatting(field, "item_separator",
                                    {"item_separator": ThemeRef("separators", "list")})
    mapping = deep_get(field, DictPath("formatting#mapping"), {})
    field_formatters = []
    for field_formatter in deep_get(field, DictPath("formatting#field_formatters"), []):
        field_formatters.append(deep_get(field_formatter_allowlist, DictPath(field_formatter)))

    # FIXME: we probably want this to be per field
    unit = deep_get(field, DictPath("formatting#unit"), "")

    tmp_field["generator"] = generator
    if "align" in field:
        align = deep_get(field, DictPath("align"), "left")
        tmp_field["ralign"] = align == "right"

    formatting = {
        "args": formatter_args,
        "item_separator": item_separator,
        "field_separators": field_separators,
        "field_colors": field_colors,
        "ellipsise": ellipsise,
        "ellipsis": ellipsis,
        "field_prefixes": field_prefixes,
        "field_suffixes": field_suffixes,
        "mapping": mapping,
        "field_formatters": field_formatters,
        "unit": unit,
    }

    tmp_field["formatting"] = formatting

    return tmp_field
