# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr, ansithemeprint

from clustermanagementtoolkit.cmtio_yaml import secure_read_yaml

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import SecurityChecks
from clustermanagementtoolkit.cmttypes import deep_get


def ansible_print_action_summary(playbooks: list[tuple[list[ANSIThemeStr], FilePath]]) -> None:
    """
    Given a list of playbook paths, print a summary of the actions that will be performed.

        Parameters:
            playbook (str): The name of the playbook to print a summary for
    """
    if not isinstance(playbooks, list):
        raise TypeError(f"playbooks is type: {type(playbooks)}, expected: {list}")

    if not playbooks:
        raise ValueError("playbooks is empty")

    if not (isinstance(playbooks[0], tuple) and len(playbooks[0]) == 2
            and isinstance(playbooks[0][0], list) and isinstance(playbooks[0][1], (FilePath, str))):
        raise TypeError("playbooks[] is wrong type; "
                        f"expected: [([{ANSIThemeStr}], {FilePath})]")

    # We do not want to check that parent resolves to itself,
    # because when we have an installation with links directly to the git repo
    # the playbooks directory will be a symlink
    checks = [
        SecurityChecks.RESOLVES_TO_SELF,
        SecurityChecks.PARENT_OWNER_IN_ALLOWLIST,
        SecurityChecks.OWNER_IN_ALLOWLIST,
        SecurityChecks.PARENT_PERMISSIONS,
        SecurityChecks.PERMISSIONS,
        SecurityChecks.EXISTS,
        SecurityChecks.IS_FILE,
    ]

    ansithemeprint([ANSIThemeStr("\n• ", "separator"),
                    ANSIThemeStr("Playbooks to be executed:", "action")])
    for playbook in playbooks:
        playbook_string, playbook_path = playbook
        playbook_data = secure_read_yaml(FilePath(playbook_path), checks=checks)

        ansithemeprint(playbook_string + [ANSIThemeStr(" (path: ", "default"),
                                          ANSIThemeStr(f"{playbook_path}", "path"),
                                          ANSIThemeStr(")", "default")])
        # None of our playbooks have more than one play per file
        summary = deep_get(playbook_data[0], DictPath("vars#metadata#summary"), {})
        if not summary:
            ansithemeprint([ANSIThemeStr("      Error", "error"),
                            ANSIThemeStr(": playbook lacks a summary; "
                                         "please file a bug report unless it's a "
                                         "locally modified playbook!", "default")],
                           stderr=True)
        for section_description, section_data in summary.items():
            ansithemeprint([ANSIThemeStr(f"      {section_description}:", "emphasis")])
            for section_item in section_data:
                description = deep_get(section_item, DictPath("description"), "")
                ansithemeprint([ANSIThemeStr(f"        {description}", "default")])
