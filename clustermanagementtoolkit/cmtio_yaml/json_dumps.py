# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Dump a Python object to JSON.
"""

import json
from typing import Any

# ujson is much faster than json, but it might not be available
try:
    import ujson
    has_ujson = True  # pylint: disable=invalid-name
except ModuleNotFoundError:
    has_ujson = False  # pylint: disable=invalid-name

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def json_dumps(obj: dict[str, Any] | list[dict[str, Any]], **kwargs: Any) -> str:
    """
    Dump Python object to JSON in text format; will try to dump using ujson if available;
    will fallback to json if ujson isn't available or if ujson fails with TypeError.

        Parameters:
            obj (dict|[dict]): The JSON object to dump
            **kwargs (dict[str, Any]): Keyword arguments
                indent (int): Indentation (default: 2)
                escape_forward_slashes (bool): Escape forward slashes (default: False);
                                               only used by ujson.
        Returns:
            (str): The serialized JSON object
        Raises:
            ValueError: If parsing fails when using ujson
            json.decoder.JSONDecodeError: If parsing fails when using json
    """
    indent = deep_get(kwargs, DictPath("indent"), 2)
    escape_forward_slashes = deep_get(kwargs, DictPath("escape_forward_slashes"), False)
    if has_ujson:
        try:
            # pylint: disable-next=c-extension-no-member
            return ujson.dumps(obj, indent=indent, escape_forward_slashes=escape_forward_slashes,
                               reject_bytes=True)
        except TypeError:
            pass

    # We'll end up here either if ujson isn't installed, or if the dumped data contains bytes.
    return json.dumps(obj, indent=indent)
