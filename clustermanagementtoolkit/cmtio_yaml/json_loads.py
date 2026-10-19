# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Load JSON data; will use whatever importer is the fastest available.
"""

import json

# orjson is faster than both ujson and json, but might not be available.
try:
    import orjson
    has_orjson = True  # pylint: disable=invalid-name
except ModuleNotFoundError:
    has_orjson = False  # pylint: disable=invalid-name

# ujson is much faster than json, but it might not be available.
try:
    import ujson
    has_ujson = True  # pylint: disable=invalid-name
except ModuleNotFoundError:
    has_ujson = False  # pylint: disable=invalid-name


def json_loads(string: str | bytes) -> dict | list[dict]:
    """
    Load a string of JSON data.

        Parameters:
            string (str | bytes): The string representation of JSON.
        Returns:
            (dict | list[dict]): The JSON data
    """
    if isinstance(string, bytes):
        string = string.decode("utf-8", errors="replace")
    if has_orjson:
        return orjson.loads(string)  # pylint: disable=no-member
    if has_ujson:
        return ujson.loads(string)  # pylint: disable=c-extension-no-member
    return json.loads(string)
