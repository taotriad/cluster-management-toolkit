# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Show a percentage bar that can be made up of multiple subsets.
"""

from clustermanagementtoolkit.curses_helper.themestr import ThemeAttr
from clustermanagementtoolkit.curses_helper.themestr import ThemeRef
from clustermanagementtoolkit.curses_helper.themestr import ThemeStr


# pylint: disable-next=too-many-locals
def percentagebar(minx: int, maxx: int, total: int,
                  subsets: list[tuple[int, ThemeRef]]) -> list[ThemeRef | ThemeStr]:
    """
    Draw a bar of multiple subsets that sum up to a total.

        Parameters:
            minx (int): The starting position of the percentage bar
            maxx (int): The ending position of the percentage bar
            total (int): The total sum
            subsets (list(subset, themeref)):
                subset (int): The fraction of the total that this subset represents
                themeref (ThemeRef): The theme reference to use for this subset
                                     Note: The string part of the ThemeRef
                                     will be truncated or repeated as necessary.
        Returns:
            (ThemeArray): The themearray with the percentage bar
    """
    themearray: list[ThemeRef | ThemeStr] = []

    bar_width: int = maxx - minx + 1
    subset_total: int = 0

    if total > 0:
        for subset in subsets:
            pct, themeref = subset
            subset_width = int((pct / total) * bar_width)
            subset_total += subset_width
            refarray = themeref.to_themearray()
            if len(refarray) > 1:
                raise ValueError("parcentagebar() cannot handle ThemeRef "
                                 "with multiple ThemeStr")
            refthemestr = refarray[0]
            refstr = str(refthemestr)
            refattr = refthemestr.get_themeattr()
            newstr = refstr * (subset_width // len(refstr)) + refstr[0:subset_width % len(refstr)]
            themearray.append(ThemeStr(newstr, refattr))

    # Pad to full width
    themearray.append(ThemeStr("".ljust(bar_width - subset_total),
                               ThemeAttr("types", "generic")))
    return themearray
