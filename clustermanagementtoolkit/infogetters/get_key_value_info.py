# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An infogetter for key/value data.
"""

import base64
from typing import Any

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_key_value_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for key/value-based information.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _vlist (dict[str, Any]): The dict of key/value objects
        Returns:
            ([dict]): A list with info
    """
    info: list[dict] = []

    if not (vlist := deep_get(kwargs, DictPath("_vlist"))):
        return info

    for key, value in vlist.items():
        decoded_value: str | bytes = ""

        vtype, value = cmtlib.decode_value(value)
        vlen = len(value)
        decoded_value = value

        if not vlen:
            value = ""
            vtype = "empty"

        if vtype.startswith("base64-utf-8"):
            fully_decoded_value: str | bytes = \
                base64.b64decode(decoded_value).decode("utf-8", errors="replace")
        else:
            fully_decoded_value = decoded_value

        if len(decoded_value) > 8192 and value:
            vtype = f"{vtype} [truncated]"
            decoded_value = value[0:8192 - 1]

        ref = {
            "key": key,
            "value": value,
            "decoded_value": decoded_value,
            "fully_decoded_value": fully_decoded_value,
            "vtype": vtype,
            "vlen": vlen,
        }
        info.append({
            "key": key,
            "ref": ref,
            "decoded_value": decoded_value,
            "value": value,
            "vtype": vtype,
            "vlen": vlen,
        })

    return info
