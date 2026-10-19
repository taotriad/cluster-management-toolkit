# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from datetime import datetime
import sys
from typing import Any, cast
try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import yaml; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install PyYAML`; aborting.")

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmtlib import get_since

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr

from clustermanagementtoolkit import generators


# pylint: disable-next=too-many-locals,too-many-branches
def format_key_value(lines: dict[str, Any], **kwargs: Any) -> list[list[ThemeRef | ThemeStr]]:
    """
    key[:type]:value formatter; returns the text with syntax highlighting for key:value data.

        Parameters:
            lines (list[str]): A list of strings representing a YAML-dump
            *or*
            lines (str): A string with newlines that should be split representing a YAML-dump
            *or*
            lines (dict[str, Any]): A dict
            **kwargs (dict[str, Any]): Keyword arguments
                separator (dict[str, str]): The type of separator to use
                sort (bool): Should the data be sorted?
                typed (bool): Should the data be interpreted as key:type:value?
                value_mappings (dict[dict[str, str]]): Map formatting
                value_type (str): type to use if data isn't typed; default is str
                override_types (dict[str, str]): Override type for specified keys
        Returns:
            list[themearray]: A list of themearrays
    """
    typed = deep_get(kwargs, DictPath("typed"), False)
    sort = deep_get(kwargs, DictPath("sort"), False)
    value_type = deep_get(kwargs, DictPath("value_type"), "default")
    override_types: dict[str, str] = deep_get(kwargs, DictPath("override_types"), {})
    value_mappings: dict[str, str] = deep_get(kwargs, DictPath("value_mappings"), {})
    separator_type: str = deep_get(kwargs, DictPath("separator#type"), "keyvalue")
    selected: bool = False

    dumps: list[list[ThemeRef | ThemeStr]] = []

    if isinstance(lines, list):
        lines = "\n".join(lines)
    if isinstance(lines, str):
        lines = yaml.safe_load(lines)

    if sort:
        lines = dict(natsorted(lines.items()))

    for key, d in lines.items():
        if not typed:
            d = {value_type: d}
        for vtype, value in d.items():
            vtype = deep_get(override_types, DictPath(key), vtype)
            match key, vtype, value:
                case key, _, _ if key in value_mappings:
                    context = deep_get(value_mappings, DictPath(f"{key}#{value}#context"), "types")
                    ftype = deep_get(value_mappings, DictPath(f"{key}#{value}#type"), "generic")
                    formatted_value: ThemeStr | list[ThemeRef | ThemeStr] = \
                        ThemeStr(value, ThemeAttr(context, ftype))
                case _, "age", _:
                    formatted_value = \
                        generators.format_numerical_with_units(f"{get_since(value)}",
                                                               selected, ftype="age")
                case _, "timestamp", _:
                    formatted_value = generators.format_timestamp(value, selected)
                case _, _, value if isinstance(value, datetime):
                    formatted_value = generators.format_timestamp(value, selected)
                case _, "bool" | "boolean", _:
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))
                case _, _, _ if isinstance(value, bool):
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))
                case _, "str" | "string", _:
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))
                case _, "hex", _ if isinstance(value, (str, int)):
                    formatted_value = \
                        generators.format_numerical_with_units(str(value), selected,
                                                               ftype="numerical",
                                                               non_units=set("0123456789abcdefABCDEF"))  # noqa: E501 pylint: disable=line-too-long
                case _, "int" | "integer" | "float", _:
                    try:
                        formatted_value = \
                            generators.format_numerical_with_units(value, selected,
                                                                   ftype="numerical")
                    except TypeError:
                        formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))
                case _, _, value if isinstance(value, (float, int)):
                    formatted_value = \
                        generators.format_numerical_with_units(str(value), selected,
                                                               ftype="numerical")
                case _, "list" | "tuple", _:
                    formatted_value = generators.format_list(list(value), fieldlen=0, pad=False)
                case _, _, value if isinstance(value, (list, tuple)):
                    formatted_value = generators.format_list(list(value), fieldlen=0, pad=False)
                case _, _, _:
                    formatted_value = ThemeStr(f"{value}", ThemeAttr("types", "generic"))

            if isinstance(formatted_value, list):
                dumps.append([
                    cast(ThemeRef | ThemeStr, ThemeStr(key, ThemeAttr("types", "key"))),
                    ThemeRef("separators", separator_type),
                ] + formatted_value)
            else:
                dumps.append([
                    ThemeStr(key, ThemeAttr("types", "key")),
                    ThemeRef("separators", separator_type),
                    formatted_value,
                ])

    return dumps
