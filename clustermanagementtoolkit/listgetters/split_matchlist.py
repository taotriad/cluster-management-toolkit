# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Given a list split it into four types of matches;
exact matches, prefix-matches, suffix-matches, infix-matches.
"""


def split_matchlist(matchlist: list[str]) -> tuple[tuple[str, ...], tuple[str, ...],
                                                   tuple[str, ...], tuple[str, ...]]:
    """
    Takes a list and splits it into four types of match lists:
    exact matches (for entries in the matchlist that doesn't start or end with *)
    prefixes (for entries in the matchlist that start with *)
    suffixes (for entries in the matchlist that end with *)
    ins (for entries in the matchlist that start and end with *).

        Parameters:
            matchlist ([str]): A list of strings to match against
        Returns:
            (((str, ...), (str, ...), (str, ...), (str, ...))):
                ((str, ...)): Strings to match with ==
                ((str, ...)): Strings to match with .startswith()
                ((str, ...)): Strings to match with .endswith()
                ((str, ...)): Strings to match with in
    """
    exacts: list[str] = []
    prefixes: list[str] = []
    suffixes: list[str] = []
    ins: list[str] = []

    for item in matchlist:
        if item.startswith("*") and item.endswith("*"):
            ins.append(item[1:-1])
        elif item.endswith("*"):
            prefixes.append(item[:-1])
        elif item.startswith("*"):
            suffixes.append(item[1:])
        else:
            exacts.append(item)
    return tuple(exacts), tuple(prefixes), tuple(suffixes), tuple(ins)
