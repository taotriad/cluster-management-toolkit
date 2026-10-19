# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def match_name(matchrule: str, name: str) -> bool:
    """
    Match a matchrule against a name. Rules starting with ^ will be matched
    with startswith(), rules ending with "$" will be matched with "endwith(),
    rules starting with "^" and ending with "$" will be matched with ==.
    Default behaviour is startswith.

        Parameters:
            matchrule (str): The rule to use for matching
            name (str): The name to match against the rule
        Return:_
            (bool): True if the name matches the rule, False if not
    """
    matchtype: str = "startswith"

    # Empty rules always matches
    if not matchrule:
        return True

    if matchrule.startswith("^") and matchrule.endswith("$"):
        matchrule = matchrule[1:-1]
        matchtype = "equals"
    elif matchrule.endswith("$"):
        matchrule = matchrule[:-1]
        matchtype = "endswith"

    if matchtype == "startswith":
        return name.startswith(matchrule)
    if matchtype == "endswith":
        return name.endswith(matchrule)
    return matchrule == name
