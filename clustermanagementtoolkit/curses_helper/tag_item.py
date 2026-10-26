# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Add a UID to the tagged set.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def tag_item(item: dict | None) -> None:
    """
    Add the UID of item to the tagged set.

        Parameters:
            item (dict[Any, Any] | None): The item to add to the tagged set.
    """
    if item is not None and (uid := deep_get(item, DictPath("__uid"))):
        CursesConfiguration.tagged_items.add(uid)
