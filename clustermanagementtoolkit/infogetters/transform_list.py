# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a list or dict, modify the data according to a transformation ruleset.
"""

import re
import sys
from typing import Any

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def transform_list(vlist: list | dict, transform: dict) -> list[Any]:
    """
    Given data as a list or dict, modify the data according the rules
    in a transformation ruleset.

        Parameters:
            sorted (booled): Should the result be sorted? True to sort, False to keep order
            key_regexes: Regexes to apply to the key
            key_groups: Regex groups to extract from the key
            key_join: Separator to use when joining the key groups
            key_defaults: Default values to use if the key regexes doesn't match
            value_regexes: Regexes to apply to the value
            value_groups: Regex groups to extract from the value
            value_join: Separator to use when joining the value groups
            value_defaults: Default values to use if the value regexes doesn't match
            output: The expected output; can be any combination of key, value
    """
    sort: bool = deep_get(transform, DictPath("sorted"), False)
    key_regexes: list[str] = deep_get(transform, DictPath("key#regex"), [])
    key_groups: list[int] = deep_get(transform, DictPath("key#groups"), [])
    key_join = deep_get(transform, DictPath("key#join"))
    key_defaults: list = deep_get(transform, DictPath("key#default"), [])
    value_regexes: list[str] = deep_get(transform, DictPath("value#regex"), [])
    value_groups: list[int] = deep_get(transform, DictPath("value#groups"), [])
    value_join = deep_get(transform, DictPath("value#join"))
    value_defaults: list = deep_get(transform, DictPath("value#default"), [])
    output: list[str] = deep_get(transform, DictPath("output"), ["key", "value"])

    result: list = []

    # This handles both lists and dicts
    # pylint: disable-next=too-many-nested-blocks
    for key in vlist:
        if not isinstance(vlist, dict):
            value = None
        else:
            value = vlist[key]

        key_data = []

        if key is None:
            continue

        key = str(key)

        if isinstance(key_regexes, str):
            key_regexes = [key_regexes]
        if not key_regexes:
            key_data.append(key)
        else:
            for _regex in key_regexes:
                re_tmp: re.Match | None = re.match(_regex, key)
                if re_tmp is not None:
                    for group in key_groups:
                        if group < len(re_tmp.groups()):
                            _tmp2 = re_tmp.groups()[group]
                            if _tmp2 is None and group < len(key_defaults):
                                key_data.append(key_defaults[group])
                            else:
                                key_data.append(_tmp2)
                if key_join is not None and len(key_data) > 1:
                    tmp = ""
                    for i, element in enumerate(key_data):
                        tmp += element
                        if i < len(key_data) - 1:
                            tmp += key_join[min(i, len(key_join) - 1)]
                    key_data = [tmp]

        value_data = []
        for _regex in value_regexes:
            if value is None:
                continue

            value = str(value)

            if (re_tmp := re.match(_regex, value)) is not None:
                for group in value_groups:
                    if group < len(re_tmp.groups()):
                        _tmp2 = re_tmp.groups()[group]
                        if _tmp2 is None and group < len(value_defaults):
                            value_data.append(value_defaults[group])
                        else:
                            value_data.append(_tmp2)
            if value_join is not None and len(value_data) > 1:
                tmp = ""
                for i, element in enumerate(value_data):
                    tmp += element
                    if i < len(value_data) - 1:
                        tmp += value_join[min(i, len(value_join) - 1)]
                value_data = [tmp]

        tmp3: list[Any] = []
        for _output in output:
            if _output == "key":
                if len(key_data) == 1:
                    tmp3.append(key_data[0])
                else:
                    tmp3.append(tuple(key_data))
            elif _output == "value":
                if len(value_data) == 1:
                    tmp3.append(value_data[0])
                else:
                    tmp3.append(tuple(value_data))
        if len(tmp3) == 1:
            result.append(tmp3[0])
        else:
            result.append(tuple(tmp3))

    if sort:
        return natsorted(result)

    return result
