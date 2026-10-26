# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that processes values of various types.
"""

from collections.abc import Sequence
from datetime import datetime, UTC
from typing import Any, cast

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import normalise_mem_bytes_to_str
from clustermanagementtoolkit.cmtlib import normalise_mem_to_bytes
from clustermanagementtoolkit.cmtlib import normalise_cpu_usage_to_millicores

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit.curses_helper import get_theme_ref

from clustermanagementtoolkit.infogetters.__process_string import __process_string
from clustermanagementtoolkit.infogetters.__process_timestamp import __process_timestamp


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def process_value(value: Any, vtype: str | list, **kwargs: Any) -> \
        int | float | str | list[str] | tuple[str] | datetime | None:
    """
    Reformat values; returns data in a format suitable for further processing.

        Parameters:
            value (Any): The value to process
            vtype (str): The value-type
            **kwargs (dict[str, Any]): Keyword arguments
                action (str): Additional actions to perform when processing
                field_index (str): The field index for formatting of a particular kind
                field_name (str): The name of the field the data originates from
                formatter (str): Formatter to use (specifically used when processing timestamps)
                replace_quotes (str): Quote replacement policy (no, pretty, same)
                view (str): The view being processed
        Returns:
            (int|float|str|[str]|(str)|datetime): The processed value
    """
    action: str = deep_get(kwargs, DictPath("action"))
    field_index: str = deep_get(kwargs, DictPath("field_index"))
    field_name: str = deep_get(kwargs, DictPath("field_name"))
    formatter: str = deep_get(kwargs, DictPath("formatter"))
    replace_quotes: str = deep_get(kwargs, DictPath("replace_quotes"))
    newlines: str = deep_get(kwargs, DictPath("newlines"), "escape")
    view: str = deep_get(kwargs, DictPath("view"))

    override_kind = \
        deep_get_with_fallback(cmtlib.cmtconfig,
                               [DictPath(f"Views#{view}#kind_format_{field_index}"),
                                DictPath(f"Views#{view}#kind_format"),
                                DictPath(f"Global#kind_format_{field_index}"),
                                DictPath("Global#kind_format")], "mixed")

    new_value: int | float | str | list[str] | tuple[str] | datetime | None = None

    if vtype == "str":
        new_value = __process_string(value, quotes=replace_quotes, newlines=newlines)
    elif vtype in ("float", "int", "bool"):
        if isinstance(value, (list, tuple)) and action == "sum":
            new_value = sum(value)
        elif isinstance(value, tuple):
            new_value = [str(s) for s in value]
        else:
            new_value = str(value)
    elif vtype in ("cpu_usage", "cpu_usage_round"):
        if isinstance(value, list) and action == "sum":
            new_value = f"{sum(normalise_cpu_usage_to_millicores(n) for n in value):0.1f}"
        elif vtype == "cpu_usage_round":
            tmp_float = normalise_cpu_usage_to_millicores(value)
            new_value = f"{int(tmp_float / 1000)}"
        else:
            tmp_float = normalise_cpu_usage_to_millicores(value)
            new_value = f"{tmp_float:0.1f}"
    elif vtype == "mem_usage":
        if isinstance(value, list) and action == "sum":
            new_value = \
                f"{normalise_mem_bytes_to_str(sum(normalise_mem_to_bytes(n) for n in value))}"
        else:
            tmp_int = normalise_mem_to_bytes(value)
            new_value = normalise_mem_bytes_to_str(tmp_int)
    elif vtype == "disk_usage":
        new_value = cmtlib.disksize_to_human(value)
    elif vtype == "len":
        if value is None:
            new_value = "0"
        else:
            new_value = str(len(cast(str | Sequence, value)))
    elif vtype == "unix_timestamp":
        new_value = datetime.fromtimestamp(value, tz=UTC)
    elif vtype == "timestamp":
        new_value = __process_timestamp(value, action, formatter)
    elif isinstance(vtype, list):
        if isinstance(value, str):
            value = (value,)
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"Field {field_name}: type({value}) is {vtype}; "
                             f"for type {vtype} pathtype must be a multi-element type")
        _values = []
        override_kind = deep_get_with_fallback(cmtlib.cmtconfig,
                                               [DictPath(f"Views#{view}#kind_format_{field_index}"),
                                                DictPath(f"Views#{view}#kind_format"),
                                                DictPath(f"Global#kind_format_{field_index}"),
                                                DictPath("Global#kind_format")], "mixed")
        for i, data in enumerate(value):
            if i < len(vtype):
                _vtype = vtype[i]
            else:
                _vtype = "raw"
            if _vtype in ("raw", "name"):
                _values.append(data)
            elif _vtype == "kind":
                if override_kind == "skip":
                    _values.append("")
                else:
                    _values.append(data)
            elif _vtype == "api_group":
                if override_kind == "skip":
                    _values.append("")
                    continue

                if data is not None and "/" in data:
                    if override_kind == "full" or override_kind == "mixed" and "." in data:
                        _values.append(data.split("/", maxsplit=1)[0])
                    else:
                        _values.append("")
                else:
                    _values.append("")
            elif _vtype == "skip":
                _values.append("")
            else:
                raise ValueError(f"Field {field_name}: type[{i}] ({vtype}) is unknown")
        if isinstance(value, list):
            new_value = _values
        elif isinstance(value, tuple):
            new_value = tuple(_values)
    elif vtype == "raw":
        # Do not convert this type
        new_value = value
    else:
        theme = get_theme_ref()

        # Is a custom type used for theming?
        if vtype not in theme["types"]:
            raise ValueError(f"Unknown value type {vtype}; the view file is probably invalid")
        new_value = value
    return new_value
