# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given an array of StatusGroup generate a heatmap.
"""

from clustermanagementtoolkit.cmttypes import StatusGroup
from clustermanagementtoolkit.cmttypes import stgroup_mapping

from clustermanagementtoolkit.curses_helper.themearray_wrap_line import themearray_wrap_line
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


def generate_heatmap(maxwidth: int, stgroups: list[StatusGroup],
                     selected: int) -> list[list[ThemeRef | ThemeStr]]:
    """
    Given [StatusGroup] and an index to the selected item and the max width,
    generate an array of themearrays.

        Parameters:
            maxwidth (int): The maximum width of a line
            stgroups ([StatusGroup]): The status group for each item
            selected (int): The selected item (used to draw the cursor); use -1 to disable cursor
        Returns:
            ([ThemeArray]): A list of themearrays
    """
    heatmap: list[ThemeRef | ThemeStr] = []

    if not stgroups:
        return []

    # Append a dummy entry to avoid special casing
    stgroups.append(StatusGroup.UNKNOWN)

    current_status = None
    status_width = 0

    # Try to minimise the colour changes
    for i, stgroup in enumerate(stgroups):
        new_status = ThemeRef("strings", stgroup_mapping[stgroup], selected=selected == i)
        if current_status is None or current_status != new_status:
            if current_status is not None:
                # We have something to flush
                # Flush
                refarray = current_status.to_themearray()
                if len(refarray) > 1:
                    raise ValueError("generate_heatmap() cannot handle ThemeRef "
                                     "with multiple ThemeStr")
                refthemestr = refarray[0]
                refstr = str(refthemestr)
                refattr = refthemestr.get_themeattr()
                is_selected = refthemestr.get_selected()
                newstr = (refstr * (status_width // len(refstr))
                          + refstr[0:status_width % len(refstr)])
                heatmap.append(ThemeStr(newstr, refattr, selected=is_selected))
            current_status = new_status
            status_width = 1
        else:
            status_width += 1

    return themearray_wrap_line(heatmap, maxwidth + 1, wrap_marker=False)
