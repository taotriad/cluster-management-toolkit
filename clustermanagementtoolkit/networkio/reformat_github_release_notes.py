# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Helper that reformats GitHub release notes to pseudo-Markdown if necessary.
"""


def reformat_github_release_notes(changelog: str = "") -> str:
    """
    Given a release message from GitHub reformat it as (extremely) rudimentary Markdown.

        Parameters:
            changelog (str): The changelog to reformat
        Returns:
            (str): The reformatted changelog
    """
    formatted_changelog = []

    previous_line = None
    for line in changelog.splitlines():
        if previous_line is None:
            previous_line = line
            continue
        if line == "---":
            formatted_changelog.append(f"## {previous_line}")
            previous_line = None
            continue
        formatted_changelog.append(previous_line)
        previous_line = line

    if previous_line is not None:
        formatted_changelog.append(previous_line)

    return "\n".join(formatted_changelog)
