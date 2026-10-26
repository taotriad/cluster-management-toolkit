# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Attributes for lines in the Window Widget.
"""

from enum import IntFlag


class WidgetLineAttrs(IntFlag):
    """
    Special properties used by lines in windowwidgets.
    """
    # No specific attributes.
    NORMAL = 0
    # Separators start a new category; they are not selectable.
    SEPARATOR = 1
    # Disabled items are not selectable, but are not treated as a new category.
    DISABLED = 2
    # Unselectable items are not selectable, but are not skipped when navigating.
    UNSELECTABLE = 4
    # Invalid items are not selectable; to be used for parse error etc.
    INVALID = 8
