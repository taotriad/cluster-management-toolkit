# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmtlib import age_to_seconds

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_promrules_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Prometheus Rules.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _obj (dict): The dict to extract data from
        Returns:
            info ([dict]): A list with info
    """
    obj = deep_get(kwargs, DictPath("_obj"))
    info: list[dict] = []

    if obj is None:
        return []

    for group in deep_get(obj, DictPath("spec#groups"), []):
        for rule in deep_get(group, DictPath("rules")):
            name = deep_get(group, DictPath("name"))
            alert = deep_get(rule, DictPath("alert"), "")
            record = deep_get(rule, DictPath("record"), "")
            if alert and record:
                # This is an invalid entry; just ignore it
                continue
            if alert:
                rtype = "Alert"
                alertrecord = alert
            elif record:
                rtype = "Record"
                alertrecord = record
            else:
                # This is an invalid entry; just ignore it
                continue
            _extra_data = {
                "name": alertrecord,
                "group": name,
                "rtype": rtype,
            }
            if "_extra_data" not in rule:
                rule["_extra_data"] = _extra_data
            ref = rule
            age = deep_get(rule, DictPath("for"), "")
            duration = age_to_seconds(age)
            info.append({
                "group": name,
                "ref": ref,
                "rtype": rtype,
                "alertrecord": alertrecord,
                "duration": duration,
            })
    return info
