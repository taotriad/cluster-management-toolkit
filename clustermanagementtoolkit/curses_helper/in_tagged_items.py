# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Check whether a UID is in the tagged set.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def in_tagged_items(item: dict | None) -> bool:
    """
    Check whether the UID of item is in the tagged set.

        Parameters:
            item (dict[Any, Any] | None): The item to locate in the tagged set.
    """
    return item is not None \
        and deep_get(item, DictPath("__uid")) in CursesConfiguration.tagged_items
