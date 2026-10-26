# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Remove a UID for the tagged set.
"""

from clustermanagementtoolkit.curses_helper.curses_globals import CursesConfiguration

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def untag_item(item: dict | None) -> None:
    """
    Remove the UID of item from the tagged set.

        Parameters:
            item (dict[Any, Any] | None): The item to remove from the tagged set.
    """
    if item is not None and (uid := deep_get(item, DictPath("__uid"))):
        CursesConfiguration.tagged_items.discard(uid)
