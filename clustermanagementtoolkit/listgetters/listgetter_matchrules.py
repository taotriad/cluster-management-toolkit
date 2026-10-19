# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list extracted from an object using match rules.
"""

from typing import Any

from clustermanagementtoolkit.cmtlib import make_set_expression_list

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=unused-argument
def listgetter_matchrules(obj: dict, **kwargs: Any) -> tuple[list[dict], str]:
    """
    Extract match rules from an object.

        Parameters:
            obj (dict[str, Any]): The object to extract a list of matchrules from
            **kwargs (dict[str, Any]): Keyword arguments [unused]
        Returns:
            ([dict[str, Any]], str):
                ([dict]): The list of data
                (str): Always "OK"
    """
    match_list = []
    status = "OK"

    for match_any in deep_get(obj, DictPath("matchAny"), []):
        for match_feature in deep_get(match_any, DictPath("matchFeatures"), []):
            feature = deep_get(match_feature, DictPath("feature"), "")
            match_expressions_dict = deep_get(match_feature, DictPath("matchExpressions"), {})
            match_expressions = []
            for match_expression_name, match_expression in match_expressions_dict.items():
                tmp = make_set_expression_list([match_expression], key=match_expression_name)[0]
                match_expressions.append(tmp)
            match_list.append({
                "feature": f"Any:{feature}",
                "match_expressions": match_expressions,
            })

    for match_feature in deep_get(obj, DictPath("matchFeatures"), []):
        match_expressions = []
        feature = deep_get(match_feature, DictPath("feature"), "")
        match_expressions_dict = deep_get(match_feature, DictPath("matchExpressions"), {})
        match_name_dict = deep_get(match_feature, DictPath("matchName"), {})
        if match_expressions_dict:
            for match_expression_name, match_expression in match_expressions_dict.items():
                tmp = make_set_expression_list([match_expression], key=match_expression_name)[0]
                match_expressions.append(tmp)
        elif match_name_dict:
            match_expressions = make_set_expression_list([match_name_dict])
        if match_expressions:
            match_list.append({
                "feature": f"{feature}",
                "match_expressions": match_expressions,
            })

    return match_list, status
