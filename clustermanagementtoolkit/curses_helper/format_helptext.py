# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Format helptext for use in the help dialog.
"""

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr
from clustermanagementtoolkit.curses_helper.curses_helper_types import WidgetLineAttrs


def format_helptext(helptext: list[tuple[str, str]]) -> list[dict]:
    """
    Given a helptext in the format [(key, description)],
    format it in a way suitable for windowwidget.

        Parameters:
            helptext: [(str, str)]: A list of rows with keypress + effect
        Returns:
            ([dict]): The formatted helptext
    """
    formatted_helptext: list[dict] = []

    for key, description in helptext:
        formatted_helptext.append({
            "lineattrs": WidgetLineAttrs.NORMAL,
            "columns": [[ThemeStr(key, ThemeAttr("windowwidget", "highlight"))],
                        [ThemeStr(description, ThemeAttr("windowwidget", "default"))]],
            "retval": None,
        })

    return formatted_helptext
