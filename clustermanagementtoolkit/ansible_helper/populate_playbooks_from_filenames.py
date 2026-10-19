# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.ansible_helper.get_playbook_path import get_playbook_path
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.populate_playbooks_from_paths import populate_playbooks_from_paths  # noqa: E501

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr

from clustermanagementtoolkit.cmttypes import FilePath


# Add all playbooks in the array
def populate_playbooks_from_filenames(playbooks: list[FilePath]) -> list[tuple[list[ANSIThemeStr],
                                                                               FilePath]]:
    """
    Given a list of playbook names, populate a list of playbook paths.

        Parameters:
            paths ([FilePath]): A list of playbook names
        Returns:
            [([ANSIThemeStr], FilePath)]:
                ([ANSIThemeStr]): An ansithemearray with the name of the playbook
                (FilePath): The path to the playbook
        Raises:
            FilePathAuditError: The playbook exists but violates path constraints,
                                or no valid playbook was found.
    """
    playbook_paths = []

    for playbook in playbooks:
        playbook_paths.append(get_playbook_path(playbook))
    return populate_playbooks_from_paths(playbook_paths)
