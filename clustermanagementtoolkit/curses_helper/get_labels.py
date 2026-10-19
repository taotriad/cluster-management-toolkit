# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return labels/annotations.
"""

from typing import Any

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.curses_helper_types import WidgetLineAttrs


def get_labels(labels: dict[str, str]) -> list[dict]:
    """
    Get labels/annotations.

        Parameters:
            labels (dict): A dict
        Returns:
            ([dict]): A formatted list of labels suitable for the windowwidget
    """
    if labels is None:
        return None

    rlabels: list[dict[str, Any]] = []
    for key, value in labels.items():
        rlabels.append({
            "lineattrs": WidgetLineAttrs.NORMAL,
            "columns": [[ThemeStr(key, ThemeAttr("windowwidget", "default"))],
                        [ThemeStr(value.replace("\n", "\\n"),
                                  ThemeAttr("windowwidget", "highlight"))]],
            "retval": None,
        })
    return rlabels
