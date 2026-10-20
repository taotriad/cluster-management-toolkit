# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A formatter for Markdown tables.
"""

from typing import cast

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef
from clustermanagementtoolkit.curses_helper import ThemeStr
from clustermanagementtoolkit.curses_helper import themearray_compact
from clustermanagementtoolkit.curses_helper import themearray_len
from clustermanagementtoolkit.curses_helper import themearray_split
from clustermanagementtoolkit.curses_helper import themearray_strip
from clustermanagementtoolkit.curses_helper import themearray_to_string


def format_markdown_table(lines: list[list[ThemeRef | ThemeStr]]) -> list[list[ThemeStr]]:
    """
    Given suitable data create a table from ThemeArray-formatted Markdown.

        Parameters:
            lines ([[ThemeRef | ThemeStr]]): A list of themearrays
        Returns:
            ([[ThemeStr]])): A reformatted list of themearrays
    """
    headers: list[list[ThemeStr]] = []

    headers = themearray_split(themearray_compact(lines[0]), separator="|")
    headers = [themearray_compact(cast(list[ThemeRef | ThemeStr], header)) for header in headers]
    headers = [themearray_strip(header) for header in headers]

    column_count: int = len(headers) * 2 + 1
    widths: list[int] = \
        [themearray_len(cast(list[ThemeRef | ThemeStr], header)) for header in headers]
    i: int = 0

    rows: list[list[ThemeStr]] = []

    # Calculate the widths; skip the headers
    for line in lines[2:]:
        row = themearray_split(themearray_compact(line), separator="|")
        row = [themearray_compact(cast(list[ThemeRef | ThemeStr], segment)) for segment in row]
        row = [themearray_strip(segment) for segment in row]
        for i, field in enumerate(row):
            try:
                widths[i] = max(themearray_len(cast(list[ThemeRef | ThemeStr], field)), widths[i])
            except IndexError:
                pass

    # We've got the widths, time to construct the table:

    # First the top line
    columns: list[list[ThemeStr]] = [[] for n in range(column_count)]
    for i in range(len(headers)):
        columns[i * 2] = [ThemeStr("┬", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = [ThemeStr("".ljust(widths[i], "─"), ThemeAttr("types", "generic"))]
    columns[0] = [ThemeStr("┌", ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("┐", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Now the header
    columns = [[] for n in range(column_count)]
    for i, header in enumerate(headers):
        # reformatted header (unless explicitly formatted)
        if len(header) == 1:
            header = [ThemeStr(themearray_to_string(cast(list[ThemeRef | ThemeStr], header)),
                               ThemeAttr("types", "markdown_table_header"))]
        columns[i * 2] = [ThemeStr("│", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = themearray_strip(header) \
                         + [ThemeStr("".ljust(widths[i]
                                              - themearray_len(cast(list[ThemeRef | ThemeStr],
                                                                    header))),
                                     ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("│", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Separator between header and data
    columns = [[] for n in range(column_count)]
    for i in range(len(headers)):
        columns[i * 2] = [ThemeStr("┼", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = [ThemeStr("".ljust(widths[i], "─"), ThemeAttr("types", "generic"))]
    columns[0] = [ThemeStr("├", ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("┤", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Data
    for line in lines[2:]:
        columns = [[] for n in range(column_count)]
        row = themearray_split(themearray_compact(line), separator="|")
        row = [themearray_compact(cast(list[ThemeRef | ThemeStr], segment)) for segment in row]
        row = [themearray_strip(segment) for segment in row]
        for i, field in enumerate(row):
            columns[i * 2] = [ThemeStr("│", ThemeAttr("types", "generic"))]
            data = field
            columns[i * 2 + 1] = data \
                + [ThemeStr("".ljust(widths[i]
                                     - themearray_len(cast(list[ThemeRef | ThemeStr], data))),
                            ThemeAttr("types", "generic"))]
        columns.append([ThemeStr("│", ThemeAttr("types", "generic"))])
        rows.append(themearray_compact([x for xx in columns for x in xx]))

    # Finally the bottom line
    columns = [[] for n in range(column_count)]
    for i in range(len(headers)):
        columns[i * 2] = [ThemeStr("┴", ThemeAttr("types", "generic"))]
        columns[i * 2 + 1] = [ThemeStr("".ljust(widths[i], "─"), ThemeAttr("types", "generic"))]
    columns[0] = [ThemeStr("└", ThemeAttr("types", "generic"))]
    columns.append([ThemeStr("┘", ThemeAttr("types", "generic"))])
    rows.append(themearray_compact([x for xx in columns for x in xx]))

    return rows
