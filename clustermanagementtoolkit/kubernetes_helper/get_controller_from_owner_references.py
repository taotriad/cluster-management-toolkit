# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a list of owner references, extract the controller.
"""

import re

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_controller_from_owner_references(owner_references: list[dict]) \
        -> tuple[tuple[str, str], str]:
    """
    Given an owner reference list, extract the controller (if any).

        Parameters:
            owner_references ([dict]): The list of owner references
        Returns:
            (((str, str), str)): A tuple made up of:
                ((str, str)): The controller kind
                (str): The controller name
    """
    controller = (("", ""), "")
    if owner_references is not None:
        api_group_regex = re.compile(r"^(.*)/.*")

        for owr in owner_references:
            if deep_get(owr, DictPath("controller"), False):
                api_version = deep_get(owr, DictPath("apiVersion"), "")
                tmp = api_group_regex.match(api_version)
                if tmp is not None:
                    api_group = tmp[1]
                else:
                    api_group = ""
                kind = (deep_get(owr, DictPath("kind")), api_group)
                controller = (kind, deep_get(owr, DictPath("name"), ""))

    return controller
