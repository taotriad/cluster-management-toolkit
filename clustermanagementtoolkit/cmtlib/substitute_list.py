# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def substitute_list(strlist: list[str], substitutions: dict) -> list[str]:
    """
    Substitutes substrings in all strings in a list.

        Parameters:
            string ([str]): A list with the strings to perform substitutions on
            substitutions (dict): A dict where key is the substring to match against,
                                  and value is the replacement for that substring
        Returns:
            ([str]): The list of strings with substitutions performed
    """
    if strlist is not None:
        for key, value in substitutions.items():
            strlist = [s.replace(key, value)
                       if (s is not None and value is not None)
                       else s for s in strlist]
    return strlist
