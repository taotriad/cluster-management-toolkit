# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Check for matches in a matchlist.
"""

from clustermanagementtoolkit.listgetters.split_matchlist import split_matchlist


def check_matchlists(item: str,
                     exacts: tuple[str, ...], prefixes: tuple[str, ...],
                     suffixes: tuple[str, ...], ins: tuple[str, ...]) -> bool:
    """
    Check whether a string has a match in a set of matchlists.

        Parameters:
            item (str): The item to match against the matchlists
            exacts ((str, ...)): A tuple of exact matches
            prefixes ((str, ...)): A tuple of prefix matches
            suffixes ((str, ...)): A tuple of suffix matches
            ins ((str, ...)): A tuple of infix matches
        Returns:
            (bool): True if the item matches any of the match items
    """
    if item in exacts:
        return True
    for in_ in ins:
        if in_ in item:
            return True
    return bool(prefixes) and item.startswith(prefixes) \
            or bool(suffixes) and item.endswith(suffixes)


# Takes an unprocessed matchlist, splits it into individual matchlists, and checks for matches
def check_matchlist(item: str, matchlist: list[str]) -> bool:
    """
    Given a string and a list of match items, check whether the string matches
    any of the match items.

        Parameters:
            matchlist ([str]): A list of strings to match against
        Returns:
            (bool): True if the item matches any of the match items
    """
    exacts, prefixes, suffixes, ins = split_matchlist(matchlist)
    return check_matchlists(item, exacts=exacts, prefixes=prefixes, suffixes=suffixes, ins=ins)
