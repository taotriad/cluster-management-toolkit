# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns fields from a list of dicts.
"""

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import get_since
from clustermanagementtoolkit.cmtlib import make_cel_expression
from clustermanagementtoolkit.cmtlib import make_label_selector
from clustermanagementtoolkit.cmtlib import make_set_expression
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_list_fields(obj: dict, **kwargs: Any) -> list[Any]:
    """
    Get the specified fields from a dict list in list format.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str|[str]): The path to the dict (optionally with fallback)
                fields ([str]): The fields to return data from
                nested_fields ([[str]]): A list of field lists
                pass_ref (bool): Pass a reference to the object?
                override_types ([str]): List of override-types for the list fields
        Returns:
            list[dict]: A list of data
    """
    vlist: list[Any] = []

    # pylint: disable-next=too-many-nested-blocks
    if "path" in kwargs and ("fields" in kwargs or "nested_fields" in kwargs):
        raw_path = deep_get(kwargs, DictPath("path"))
        pass_ref = deep_get(kwargs, DictPath("pass_ref"), False)
        override_types = deep_get(kwargs, DictPath("override_types"), [])

        if isinstance(raw_path, str):
            raw_path = [raw_path]

        paths = []
        for path in raw_path:
            paths.append(DictPath(path))
        tmp_fields = deep_get(kwargs, DictPath("fields"), [])
        nested_fields = deep_get(kwargs, DictPath("nested_fields"), [tmp_fields])

        for fields in nested_fields:
            for item_index, item in enumerate(deep_get_with_fallback(obj, paths, [])):
                tmp = []
                for i, field in enumerate(fields):
                    default = ""
                    value_type = "value"
                    quote = False
                    index_template = "<<<index>>>"
                    if isinstance(field, dict):
                        default = deep_get(field, DictPath("default"), "")
                        index_template = deep_get(field, DictPath("index_template"), "<<<index>>>")
                        value_type = deep_get(field, DictPath("value"), "value")
                        quote = deep_get(field, DictPath("quote"), False)
                        # Needs to be last here, since it overwrites field
                        field = deep_get(field, DictPath("path"), "")

                    # Instead of inserting a field here we insert a field containing list index
                    if value_type == "index":
                        index_str = cmtlib.substitute_string(index_template,
                                                             {"<<<index>>>": str(item_index)})
                        tmp.append(index_str)
                        continue

                    if isinstance(field, str):
                        field = [DictPath(field)]

                    value_ = deep_get_with_fallback(item, field, default)
                    if value_type == "key":
                        for key in field:
                            if key in item:
                                value = key
                    elif value_type == "label_selector":
                        tmp_selectors = []
                        for tmp_selector in value_:
                            tmp_selectors.append(make_label_selector(tmp_selector))
                        value = ",".join(tmp_selectors)
                    elif value_type == "cel":
                        value = make_cel_expression(value_)
                    elif value_type == "match_expression":
                        value = make_set_expression(value_)
                    elif (isinstance(value_, list)
                            or (i < len(fields) and i < len(override_types)
                                and override_types[i] == "list")):
                        value = ", ".join(value_)
                    elif (isinstance(value_, dict)
                            or (i < len(fields) and i < len(override_types)
                                and override_types[i] == "dict")):
                        value = ", ".join(f"{key}:{val}" for (key, val) in value_.items())
                    # We do not need to check for bool, since it is a subclass of int
                    elif (isinstance(value_, (int, float))
                            or (i < len(fields) and i < len(override_types)
                                and override_types[i] == "str")):
                        value = str(value_)
                    elif isinstance(value_, str):
                        if (i < len(fields) and i < len(override_types)
                                and override_types[i] == "timestamp"):

                            # Empty string or None indicates a missing timestamp
                            if value_ is None or not value_:
                                value = "<unset>"
                            else:
                                timestamp = timestamp_to_datetime(value_)
                                value = f"{timestamp.astimezone():%Y-%m-%d %H:%M:%S}"
                        elif (i < len(fields) and i < len(override_types)
                                and override_types[i] == "age"):
                            if value_ is None:
                                value = "<unset>"
                            else:
                                timestamp = timestamp_to_datetime(value_)
                                value = cmtlib.seconds_to_age(get_since(timestamp))
                        else:
                            value = value_
                    else:
                        raise ValueError(f"Unhandled type {type(value_)} for {field}={value}")
                    if quote:
                        value = f"\"{value}\""
                    tmp.append(value)
                if pass_ref:
                    vlist.append({"fields": tmp, "ref": item})
                else:
                    vlist.append(tmp)
    return vlist
