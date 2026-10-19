# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_strategy_info(**kwargs: Any) -> list[dict]:
    """
    Infogetter for Telemetry Aware Scheduling policies.

        Parameters:
            **kwargs (dict[str, Any]): Keyword arguments
                _obj (dict): The dict to extract data from
        Returns:
            ([dict]): A list with info
    """
    obj = deep_get(kwargs, DictPath("_obj"))
    info = []

    if obj is None:
        return []

    labeling_rules = deep_get(obj, DictPath("spec#strategies#labeling#rules"), [])
    deschedule_rules = deep_get(obj, DictPath("spec#strategies#deschedule#rules"), [])
    dontschedule_rules = deep_get(obj, DictPath("spec#strategies#dontschedule#rules"), [])
    scheduleonmetric_rules = deep_get(obj, DictPath("spec#strategies#scheduleonmetric#rules"), [])

    if deschedule_rules:
        strategy = "deschedule"
        rule = deschedule_rules[0]

        # Even though this is an array there's only one rule
        name = deep_get(rule, DictPath("metricname"), "")
        operator = deep_get(rule, DictPath("operator"), "")
        target = deep_get(rule, DictPath("target"), -1)
        info.append({
            "strategy": strategy,
            "name": name,
            "operator": operator,
            "target": target,
            "labels": [],
        })

    if dontschedule_rules:
        strategy = "dontschedule"
        # dontschedule can have multiple rules; if it does we build a hackish tree
        if len(dontschedule_rules) > 1:
            info.append({
                "strategy": strategy,
                "name": "",
                "operator": "",
                "target": -1,
                "labels": [],
            })
            for rule in dontschedule_rules:
                name = rule.get("metricname", "")
                operator = rule.get("operator", "")
                target = rule.get("target", -1)
                info.append({
                    "strategy": "",
                    "name": rule.get("metricname", ""),
                    "operator": rule.get("operator", ""),
                    "target": rule.get("target", -1),
                    "labels": [],
                })
        else:
            rule = dontschedule_rules[0]
            name = rule.get("metricname", "")
            operator = rule.get("operator", "")
            target = rule.get("target", -1)
            info.append({
                "strategy": strategy,
                "name": name,
                "operator": operator,
                "target": target,
                "labels": [],
            })

    if scheduleonmetric_rules:
        strategy = "scheduleonmetric"
        rule = deschedule_rules[0]

        # Even though this is an array there's only one rule
        name = rule.get("metricname", "")
        operator = rule.get("operator", "")
        target = rule.get("target", -1)
        info.append({
            "strategy": strategy,
            "name": name,
            "operator": operator,
            "target": target,
            "labels": [],
        })

    for rule in labeling_rules:
        strategy = "labeling"

        # Even though this is an array there's only one rule
        name = rule.get("metricname", "")
        operator = rule.get("operator", "")
        target = rule.get("target", -1)
        labels = rule.get("labels", [])
        info.append({
            "strategy": strategy,
            "name": name,
            "operator": operator,
            "target": target,
            "labels": labels,
        })

    return info
