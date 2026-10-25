# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Word wrap text.
"""


def wrap_line(string: str | list[str], wrap_width: int) -> list[str | list[str]]:
    """
    Attempt to word wrap text. If a word does not fit within a line it is emitted intact.

        Parameters:
            string (str|[str]): The string to word wrap
            wrap_width (int): The maximum line length
        Returns:
            ([str]|[[str]]): A list of strings
    """
    wrapped_line: list[str | list[str]] = []
    listlist: bool = True

    if isinstance(string, str):
        string = [string]
        listlist = False

    words: list[str] = string[0].split(" ")
    line: str = ""

    for word in words:
        if not line:
            line = word
        elif len(line) + 1 + len(word) < wrap_width:
            line = f"{line} {word}"
        else:
            if listlist:
                wrapped_line.append([line])
            else:
                wrapped_line.append(line)
            line = word
    if line:
        if listlist:
            wrapped_line.append([line])
        else:
            wrapped_line.append(line)
    return wrapped_line
