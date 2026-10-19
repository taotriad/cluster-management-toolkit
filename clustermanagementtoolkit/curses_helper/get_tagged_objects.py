# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of objects for all tagged items.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def get_tagged_objects(items: list[dict]) -> list[dict]:
    """
    Return a list of objects for all UIDs matching the tagged set.

        Parameters:
            items ([dict]): The objects to search
        Returns:
            ([dict]): A list of objects
    """
    return [d for d in items if deep_get(d, DictPath("__uid")) in CursesConfiguration.tagged_items]
