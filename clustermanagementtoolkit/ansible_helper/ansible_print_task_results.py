# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Pretty-print the result of an Ansible task run.
"""

from typing import Any

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr, ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-branches
def ansible_print_task_results(task: str,
                               msg_lines: list[str],
                               stdout_lines: list[str],
                               stderr_lines: list[str], retval: int, **kwargs: Any) -> None:
    """
    Pretty-print the result of an Ansible task run.

        Parameters:
            task (str): The name of the task
            msg_lines (list[str]): msg from tasks that do not split the output into stdout+stderr
            stdout_lines (list[str]): output from stdout
            stderr_lines (list[str]): output from stderr
            retval (int): The return value from the task
            **kwargs (dict[str, Any]): Keyword arguments
                unreachable (bool): Was the host unreachable?
                skipped (bool): Was the task skipped?
                verbose (bool): Should skipped tasks be outputted?
    """
    unreachable: bool = deep_get(kwargs, DictPath("unreachable"), False)
    skipped: bool = deep_get(kwargs, DictPath("skipped"), False)
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)

    if unreachable:
        ansithemeprint([ANSIThemeStr("• ", "separator"),
                        ANSIThemeStr(f"{task}", "error")], stderr=True)
    elif skipped:
        if verbose:
            ansithemeprint([ANSIThemeStr("• ", "separator"),
                            ANSIThemeStr(f"{task} [skipped]", "skip")], stderr=True)
            ansithemeprint([ANSIThemeStr("", "default")])
        return
    elif retval:
        ansithemeprint([ANSIThemeStr("• ", "separator"),
                        ANSIThemeStr(f"{task}", "error"),
                        ANSIThemeStr(" (retval: ", "default"),
                        ANSIThemeStr(f"{retval}", "errorvalue"),
                        ANSIThemeStr(")", "default")], stderr=True)
    else:
        ansithemeprint([ANSIThemeStr("• ", "separator"),
                        ANSIThemeStr(f"{task}", "success")])

    if msg_lines:
        ansithemeprint([ANSIThemeStr("msg:", "header")])
        for line in msg_lines:
            ansithemeprint([ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")])
        ansithemeprint([ANSIThemeStr("", "default")])

    if stdout_lines or not msg_lines and not stderr_lines:
        ansithemeprint([ANSIThemeStr("stdout:", "header")])
        for line in stdout_lines:
            ansithemeprint([ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")])
        if not stdout_lines:
            ansithemeprint([ANSIThemeStr("<no output>", "none")])
        ansithemeprint([ANSIThemeStr("", "default")])

    # If retval is not 0 we do not really care if stderr is empty
    if stderr_lines or retval:
        ansithemeprint([ANSIThemeStr("stderr:", "header")])
        for line in stderr_lines:
            ansithemeprint([ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")],
                           stderr=True)
        if not stderr_lines:
            ansithemeprint([ANSIThemeStr("<no output>", "none")])
        ansithemeprint([ANSIThemeStr("", "default")])
