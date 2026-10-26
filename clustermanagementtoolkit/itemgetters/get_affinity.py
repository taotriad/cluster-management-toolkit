# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
An itemgetter that returns a list of affinities.
"""

import re
from typing import Any

from clustermanagementtoolkit.cmtlib import make_label_selector
from clustermanagementtoolkit.cmtlib import make_set_expression

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback


# pylint: disable-next=too-many-locals,too-many-branches
def get_affinity(obj: dict, **kwargs: Any) -> list[tuple[str, str, str, str, str]]:
    """
    Get a list of affinities.

        Parameters:
            obj (dict): The object to get data from
            **kwargs (dict[str, Any]): Keyword arguments
                path (str): The path to the affinity data
        Returns:
            ([dict]): A list of conditions
    """
    affinities: list[tuple[str, str, str, str, str]] = []
    path: str = deep_get(kwargs, DictPath("path"), "spec#affinity")

    for affinity in deep_get(obj, DictPath(path), []):
        atype = affinity
        policy_regex = re.compile(r"^(ignored|preferred|required)DuringScheduling"
                                  r"(Ignored|Preferred|Required)DuringExecution$")

        for policy in deep_get(obj, DictPath(f"{path}#{atype}"), ""):
            if (re_tmp := policy_regex.match(policy)) is None:
                scheduling = "Unknown"
                execution = "Unknown"
            else:
                scheduling = re_tmp[1].capitalize()
                execution = re_tmp[2]

            selectors = ""
            for item in deep_get(obj, DictPath(f"{path}#{atype}#{policy}"), []):
                items = []
                topology = ""
                if isinstance(item, dict):
                    items = [item]
                elif isinstance(item, str):
                    items = deep_get(obj, DictPath(f"spec#affinity#{atype}#{policy}#{item}"), [])

                for selector in items:
                    weight = deep_get(selector, DictPath("weight"), "")
                    if isinstance(weight, int):
                        weight = f"/{weight}"
                    topology = deep_get_with_fallback(selector,
                                                      [DictPath("podAffinityTerm#topologyKey"),
                                                       DictPath("topologyKey")], "")
                    # We are combining a few different policies,
                    # so the expressions can be in various places; not simultaneously though
                    # hence += should be OK.
                    # The best thing would probably be to use deep_get_with_fallback though.
                    paths = [
                        DictPath("podAffinityTerm#labelSelector#matchExpressions"),
                        DictPath("podAffinityTerm#labelSelector#matchFields"),
                        DictPath("labelSelector#matchExpressions"),
                        DictPath("labelSelector#matchFields"),
                        DictPath("labelSelector#matchLabels"),
                        DictPath("preference#matchExpressions"),
                        DictPath("preference#matchFields"),
                        DictPath("matchExpressions"),
                        DictPath("matchFields"),
                    ]

                    tmp2 = deep_get_with_fallback(selector, paths)

                    if tmp2 is None:
                        continue
                    if isinstance(tmp2, list):
                        selectors = make_set_expression(tmp2)
                    elif isinstance(tmp2, dict):
                        selectors = make_label_selector(tmp2)
                    else:
                        # XXX: We have no idea how to handle this
                        continue
                    affinities.append((atype, f"{scheduling}{weight}",
                                       execution, selectors, topology))
    return affinities
