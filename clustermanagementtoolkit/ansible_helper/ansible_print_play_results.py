# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr, ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

# pylint: disable-next=line-too-long
from clustermanagementtoolkit.ansible_helper.ansible_print_task_results import ansible_print_task_results  # noqa: E501


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def ansible_print_play_results(retval: int, ansible_results: dict, **kwargs: Any) -> None:
    """
    Pretty-print the result of an Ansible play.

        Parameters:
            retval (int): The return value from the play
            ansible_results (opaque): The data from a playbook run
            **kwargs (dict[str, Any]): Keyword arguments
                verbose (bool): Should skipped tasks be outputted?
    """
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)

    count_total = 0
    count_task_total = 0
    count_no_hosts_match = 0
    count_unreachable = 0
    count_skip = 0
    count_success = 0
    count_fail = 0

    if retval and not ansible_results:
        ansithemeprint([ANSIThemeStr("Failed to execute playbook; retval: ", "error"),
                        ANSIThemeStr(f"{retval}", "errorvalue")], stderr=True)
    else:
        for host, data in ansible_results.items():
            count_total += 1

            plays = data
            header_output = False

            for play in plays:
                count_task_total += 1
                task = deep_get(play, DictPath("task"))

                no_hosts_matched = deep_get(play, DictPath("no_hosts_matched"), False)
                unreachable = deep_get(play, DictPath("unreachable"), False)
                skipped = deep_get(play, DictPath("skipped"), False)
                retval = deep_get(play, DictPath("retval"))

                if not header_output:
                    header_output = True

                    if no_hosts_matched:
                        ansithemeprint([ANSIThemeStr("[No hosts matched]", "error")])
                    elif unreachable:
                        ansithemeprint([ANSIThemeStr(f"[{host}]", "error")])
                    elif skipped:
                        ansithemeprint([ANSIThemeStr(f"[{host}]", "skip")])
                    elif not retval:
                        ansithemeprint([ANSIThemeStr(f"[{host}]", "success")])
                    else:
                        ansithemeprint([ANSIThemeStr(f"[{host}]", "error")])
                if no_hosts_matched:
                    count_no_hosts_match += 1
                elif unreachable:
                    count_unreachable += 1
                elif skipped:
                    count_skip += 1
                elif not retval:
                    count_success += 1
                else:
                    count_fail += 1

                if not no_hosts_matched:
                    msg_lines = deep_get(play, DictPath("msg_lines"), "")
                    stdout_lines = deep_get(play, DictPath("stdout_lines"), [])
                    stderr_lines = deep_get(play, DictPath("stderr_lines"), [])
                    ansible_print_task_results(task,
                                               msg_lines,
                                               stdout_lines,
                                               stderr_lines,
                                               retval,
                                               unreachable=unreachable,
                                               skipped=skipped,
                                               verbose=verbose)

                if not skipped or verbose:
                    print()

                # Only show no hosts matched and unreachable once
                if unreachable:
                    break

    if verbose:
        successful_formatting = "default"
        failed_formatting = "skip"
        unreachable_formatting = "skip"
        no_hosts_matched_formatting = "skip"
        if count_success:
            successful_formatting = "success"
        if count_fail:
            failed_formatting = "error"
        if count_unreachable:
            unreachable_formatting = "error"
        if count_no_hosts_match:
            no_hosts_matched_formatting = "error"

        ansithemeprint([ANSIThemeStr("Summary:", "default")])
        ansithemeprint([ANSIThemeStr("Total Plays: ", "phase"),
                        ANSIThemeStr(f"{count_total}", "numerical"),
                        ANSIThemeStr(" / ", "separator"),
                        ANSIThemeStr("Tasks: ", "phase"),
                        ANSIThemeStr(f"{count_task_total}", "numerical"),
                        ANSIThemeStr(", ", "separator"),
                        ANSIThemeStr("Successful: ", successful_formatting),
                        ANSIThemeStr(f"{count_success}", "numerical"),
                        ANSIThemeStr(", ", "separator"),
                        ANSIThemeStr("Failed: ", failed_formatting),
                        ANSIThemeStr(f"{count_fail}", "numerical"),
                        ANSIThemeStr(", ", "separator"),
                        ANSIThemeStr("Skipped: ", "skip"),
                        ANSIThemeStr(f"{count_skip}", "numerical"),
                        ANSIThemeStr(", ", "separator"),
                        ANSIThemeStr("Unreachable: ", unreachable_formatting),
                        ANSIThemeStr(f"{count_unreachable}", "numerical"),
                        ANSIThemeStr(", ", "separator"),
                        ANSIThemeStr("No hosts matched: ", no_hosts_matched_formatting),
                        ANSIThemeStr(f"{count_no_hosts_match}\n", "numerical")])
