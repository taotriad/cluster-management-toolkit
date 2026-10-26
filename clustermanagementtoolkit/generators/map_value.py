# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Map formatting based on values.
"""

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit import cmtlog

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import LogLevel
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr


# pylint: disable-next=too-many-locals,too-many-statements,too-many-branches
def map_value(value: Any, selected: bool = False,
              **kwargs: Any) -> tuple[ThemeRef | ThemeStr, str]:
    """
    Perform value based mappings; either by doing numerical ranges,
    or by doing string comparisons (optionally case insensitive).

        Parameters:
            value (Any): The value to map
            references (Any): The references to map against (unsupported for now)
            selected (bool): Is the string selected?
            default_field_color (ThemeAttr): The default colour to use if no mapping occurs
            **kwargs (dict[str, Any]): Keyword arguments
                mapping (dict): The mapping rules
        Returns:
            (ThemeArray, str):
                (ThemeArray): The formatted themearray
                (str): The string-representation of the value
    """
    default_field_color: ThemeAttr = \
        deep_get(kwargs, DictPath("default_field_color"), ThemeAttr("types", "generic"))

    # If we lack a mapping, use the default color for this field
    if not deep_get(kwargs, DictPath("mapping"), {}):
        return ThemeStr(value, default_field_color, selected), value

    substitutions = deep_get(kwargs, DictPath("mapping#substitutions"), {})
    ranges = deep_get(kwargs, DictPath("mapping#ranges"), [])
    source = deep_get(kwargs, DictPath("mapping#source"), "reference")
    match_case = deep_get(kwargs, DictPath("mapping#match_case"), True)
    mappings = deep_get(kwargs, DictPath("mapping#mappings"), {})

    field_colors = None

    if value in substitutions or isinstance(value, int) and f"__{value}" in substitutions:
        # We do not need to check for bool, since it is a subclass of int
        if isinstance(value, int):
            value = substitutions[f"__{value}"]
        else:
            value = substitutions[value]

        # If the substitution is a dict it is either a ThemeRef to a separator or a string,
        # or a ThemeStr
        if isinstance(value, dict):
            context: str = deep_get(value, DictPath("context"), "main")
            attr_ref: str = deep_get(value, DictPath("type"))
            string: str = deep_get(value, DictPath("string"))
            if string is None:
                themeref = ThemeRef(context, attr_ref, selected)
                return themeref, str(themeref)
            themestring = ThemeStr(string, ThemeAttr(context, attr_ref))
            return themestring, str(themestring)
        if isinstance(value, ThemeRef):
            return value, str(value)

    # OK, so we want to output output_value, but compare using reference_value.
    # Unless source is output, in which case we want to compare output value to reference value;
    # this requires min/max to be percentages.
    if isinstance(value, tuple) and ranges:
        output_value, reference_value = value
    else:
        output_value = value
        reference_value = value

    try:
        if ranges:
            if isinstance(reference_value, str):
                if "." in reference_value:
                    reference_value = float(reference_value)
                else:
                    reference_value = int(reference_value)
            if isinstance(output_value, str):
                if "." in output_value:
                    output_value = float(output_value)
                else:
                    output_value = int(output_value)
    except ValueError:
        pass

    if (reference_value is None or isinstance(reference_value, (int, float))) and ranges:
        default_index = -1
        for i, data in enumerate(ranges):
            if deep_get(data, DictPath("default"), False):
                if default_index != -1:
                    raise ValueError("Range cannot contain more than one default")
                default_index = i
                continue

            # For simplicity's sake we only support percentage comparison if both min and max
            # are percentages.
            _min = deep_get(data, DictPath("min"))
            _max = deep_get(data, DictPath("max"))

            if _min is None and _max is None:
                if reference_value is None:
                    field_colors = deep_get(data, DictPath("field_colors"))
                    break
                continue

            if isinstance(_min, str) and _min.endswith("%") \
                    and isinstance(_max, str) and _max.endswith("%"):
                try:
                    _min = int(reference_value * (int(_min[:-1]) / 100))  # type: ignore[operator]
                    _max = int(reference_value * (int(_max[:-1]) / 100))  # type: ignore[operator]
                except ValueError:
                    errmsg = [
                        [("Viewfile contains invalid min/max values in range comparison; min: ",
                         "default"),
                         (f"{_min}", "argument"),
                         (", max: ", "default"),
                         (f"{_max}", "argument")],
                    ]
                    unformatted_msg, formatted_msg = ANSIThemeStr.format_error_msg(errmsg)
                    cmtlog.log(LogLevel.ERR, msg=unformatted_msg, messages=formatted_msg)
                    _min = None
                    _max = None

            if source == "output":
                compare_value = output_value
            else:
                compare_value = reference_value
            if (_min is None or compare_value >= _min) \
                    and (_max is None or compare_value < _max):
                field_colors = deep_get(data, DictPath("field_colors"))
                break
            field_colors = deep_get(ranges[default_index], DictPath("field_colors"))
        string = str(output_value)
    elif isinstance(reference_value, (str, bool)) or not ranges:
        string = str(output_value)
        _string = string
        if not match_case:
            matched = False
            if string in mappings and string.lower() in mappings and string != string.lower():
                raise ValueError("When using match_case == False "
                                 "the mapping cannot contain keys that only differ in case")
            for key in mappings:
                if key.lower() == string.lower():
                    _string = key
                matched = True
            if not matched and "__default" in mappings:
                _string = "__default"
        elif _string not in mappings and "__default" in mappings:
            _string = "__default"
        field_colors = deep_get(mappings, DictPath(f"{_string}#field_colors"))
    else:
        raise TypeError(f"Unknown type {type(value)} for mapping/range")

    if field_colors is not None:
        context = deep_get(field_colors[0], DictPath("context"), "main")
        attr_ref = deep_get(field_colors[0], DictPath("type"))
        fmt = ThemeAttr(context, attr_ref)
    else:
        fmt = ThemeAttr("types", "generic")
    return ThemeStr(string, fmt, selected), string
