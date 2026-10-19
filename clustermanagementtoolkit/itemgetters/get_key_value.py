# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_key_value(obj: dict, **kwargs: Any) -> list[tuple[str, Any]]:
    """
    Get a list of key/value data, possibly from a string by splitting it.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the key/value-pairs to get
                value_path (str): Get the value from a nested path instead of the direct value
                ignored_keys (list[str]): Keys to skip when processing the data
        Returns:
            ([dict]): A list of key/value data
        Raises:
            TypeError: The type for value is not supported by get_key_value()
    """
    ignored_keys: list[str] = deep_get(kwargs, DictPath("ignored_keys"), [])
    value_path: str = deep_get(kwargs, DictPath("value_path"))
    vlist = []

    if (path := deep_get(kwargs, DictPath("path"), "")):
        d = deep_get(obj, DictPath(path), {})

        if isinstance(d, str):
            d = d.split(",")
            try:
                d = dict([key_value.split("=", maxsplit=1) for key_value in d])
            except ValueError as e:
                # Log + Return empty?
                raise TypeError("Could not convert list of key=value into a dict") from e
        for key_, value_ in d.items():
            if key_ in ignored_keys:
                continue
            if value_path and isinstance(value_, dict):
                value_ = deep_get(value_, DictPath(value_path))
            if isinstance(value_, (list, tuple)):
                value = ",".join(value_)
            elif isinstance(value_, dict):
                value = ",".join(f"{key}:{val}" for (key, val) in value_.items())
            # We do not need to check for bool, since it is a subclass of int,
            # and str(str) == str
            elif isinstance(value_, (int, float, str)):
                value = str(value_)
            else:
                # Log + Return empty?
                raise TypeError(f"Unhandled type {type(value_)} for {key_}={value_}")
            vlist.append((key_, value))
    return vlist
