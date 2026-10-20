# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Run an Ansible playbook.
"""

from datetime import datetime, UTC
import sys
from typing import Any

# Used by Ansible
try:
    import ansible_runner  # type: ignore[import-untyped,unused-ignore]
except ModuleNotFoundError:  # pragma: no cover
    # This is acceptable; we don't benefit from a backtrace or log message
    sys.exit("ModuleNotFoundError: Could not import ansible_runner; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install ansible-runner`; "
             "aborting.")

from clustermanagementtoolkit.ansible_helper.ansible_results_extract import ansible_results_extract
from clustermanagementtoolkit.ansible_helper.ansible_write_log import ansible_write_log
from clustermanagementtoolkit.ansible_helper.ansible_helper_types import AnsibleConfiguration

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr, ansithemeprint

from clustermanagementtoolkit.cmtpaths import ANSIBLE_INVENTORY

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def __ansible_run_event_handler_cb(data: dict) -> bool:
    if deep_get(data, DictPath("event"), "") in ("runner_on_failed", "runner_on_async_failed"):
        host = deep_get(data, DictPath("event_data#host"), "<unset>")
        task = deep_get(data, DictPath("event_data#task"), "<unset>")
        ansithemeprint([ANSIThemeStr("  • ", "separator"),
                        ANSIThemeStr("Task", "action"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{task}", "play"),
                        ANSIThemeStr(" ", "default"),
                        ANSIThemeStr("failed", "error"),
                        ANSIThemeStr(" on ", "default"),
                        ANSIThemeStr(f"{host}", "hostname")])
        for res in deep_get(data, DictPath("event_data#res#results"), []):
            msg = deep_get(res, DictPath("msg"), "")
            if msg:
                ansithemeprint([ANSIThemeStr("    ", "default"),
                                ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(":", "default")])
                ansithemeprint([ANSIThemeStr(f"      {msg}", "default")])
    elif deep_get(data, DictPath("event"), "") == "runner_on_unreachable":
        host = deep_get(data, DictPath("event_data#host"), "<unset>")
        task = deep_get(data, DictPath("event_data#task"), "<unset>")
        ansithemeprint([ANSIThemeStr("  • ", "separator"),
                        ANSIThemeStr("Task", "action"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{task}", "play"),
                        ANSIThemeStr(" ", "default"),
                        ANSIThemeStr("failed", "error"),
                        ANSIThemeStr("; ", "default"),
                        ANSIThemeStr(f"{host}", "hostname"),
                        ANSIThemeStr(" unreachable", "default")])
    return True


# pylint: disable-next=too-many-branches,too-many-statements
def __ansible_run_event_handler_verbose_cb(data: dict) -> bool:
    if deep_get(data, DictPath("event"), "") == "verbose":
        print(deep_get(data, DictPath("stdout"), ""))
    if deep_get(data, DictPath("event"), "") == "runner_on_start":
        host = deep_get(data, DictPath("event_data#host"), "<unset>")
        task = deep_get(data, DictPath("event_data#task"), "<unset>")
        ansithemeprint([ANSIThemeStr("  • ", "separator"),
                        ANSIThemeStr("Task", "action"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{task}", "play"),
                        ANSIThemeStr(" ", "default"),
                        ANSIThemeStr("started", "phase"),
                        ANSIThemeStr(" on ", "default"),
                        ANSIThemeStr(f"{host}", "hostname")])
    elif deep_get(data, DictPath("event"), "") in ("runner_on_ok", "runner_on_async_ok"):
        host = deep_get(data, DictPath("event_data#host"), "<unset>")
        task = deep_get(data, DictPath("event_data#task"), "<unset>")
        ansithemeprint([ANSIThemeStr("  • ", "separator"),
                        ANSIThemeStr("Task", "action"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{task}", "play"),
                        ANSIThemeStr(" ", "default"),
                        ANSIThemeStr("succeeded", "success"),
                        ANSIThemeStr(" on ", "default"),
                        ANSIThemeStr(f"{host}", "hostname")])
    elif deep_get(data, DictPath("event"), "") in ("runner_on_failed", "runner_on_async_failed"):
        host = deep_get(data, DictPath("event_data#host"), "<unset>")
        task = deep_get(data, DictPath("event_data#task"), "<unset>")
        ansithemeprint([ANSIThemeStr("  • ", "separator"),
                        ANSIThemeStr("Task", "action"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{task}", "play"),
                        ANSIThemeStr(" ", "default"),
                        ANSIThemeStr("failed", "error"),
                        ANSIThemeStr(" on ", "default"),
                        ANSIThemeStr(f"{host}", "hostname")])
        for res in deep_get(data, DictPath("event_data#res#results"), []):
            if "stdout_lines" in res or "stderr_lines" in res:
                item = deep_get(res, DictPath("item"), "")
                ansithemeprint([ANSIThemeStr("    ", "default"),
                                ANSIThemeStr("Item", "header"),
                                ANSIThemeStr(":", "default"),
                                ANSIThemeStr(f"{item}", "default")])
            msg = deep_get(res, DictPath("msg"), "")
            if msg:
                ansithemeprint([ANSIThemeStr("    ", "default"),
                                ANSIThemeStr("Error", "error"),
                                ANSIThemeStr(":", "default")])
                ansithemeprint([ANSIThemeStr(f"      {msg}", "default")])
            if "stdout_lines" in res or "stderr_lines" in res:
                stdout_lines = deep_get(res, DictPath("stdout_lines"), [])
                stderr_lines = deep_get(res, DictPath("stderr_lines"), [])
                if stdout_lines:
                    ansithemeprint([ANSIThemeStr("    ", "default"),
                                    ANSIThemeStr("stdout", "default"),
                                    ANSIThemeStr(":", "default")])
                    for line in stdout_lines:
                        ansithemeprint([ANSIThemeStr("      ", "default"),
                                        ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")])
                if stderr_lines:
                    ansithemeprint([ANSIThemeStr("    ", "default"),
                                    ANSIThemeStr("stderr", "error"),
                                    ANSIThemeStr(":", "default")])
                    for line in stderr_lines:
                        ansithemeprint([ANSIThemeStr("      ", "default"),
                                        ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")])

        msg_lines = deep_get(data, DictPath("event_data#res#msg"), "").splitlines()
        if msg_lines:
            ansithemeprint([ANSIThemeStr("    ", "default"),
                            ANSIThemeStr("Error", "error"),
                            ANSIThemeStr(":", "default")])
            for line in msg_lines:
                ansithemeprint([ANSIThemeStr("      ", "default"),
                                ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")])
        stdout_lines = deep_get(data, DictPath("event_data#res#stdout_lines"), [])
        stderr_lines = deep_get(data, DictPath("event_data#res#stderr_lines"), [])
        if stdout_lines:
            ansithemeprint([ANSIThemeStr("    ", "default"),
                            ANSIThemeStr("stdout", "default"),
                            ANSIThemeStr(":", "default")])
            for line in stdout_lines:
                ansithemeprint([ANSIThemeStr("      ", "default"),
                                ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")])
        if stderr_lines:
            ansithemeprint([ANSIThemeStr("    ", "default"),
                            ANSIThemeStr("stderr", "error"),
                            ANSIThemeStr(":", "default")])
            for line in stderr_lines:
                ansithemeprint([ANSIThemeStr("      ", "default"),
                                ANSIThemeStr(line.replace("\x00", "<NUL>"), "default")])
    elif deep_get(data, DictPath("event"), "") == "runner_on_unreachable":
        host = deep_get(data, DictPath("event_data#host"), "<unset>")
        task = deep_get(data, DictPath("event_data#task"), "<unset>")
        ansithemeprint([ANSIThemeStr("  • ", "separator"),
                        ANSIThemeStr("Task", "action"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{task}", "play"),
                        ANSIThemeStr(" ", "default"),
                        ANSIThemeStr("failed", "error"),
                        ANSIThemeStr("; ", "default"),
                        ANSIThemeStr(f"{host}", "hostname"),
                        ANSIThemeStr(" unreachable", "default")])
    elif deep_get(data, DictPath("event"), "") == "runner_on_skipped":
        host = deep_get(data, DictPath("event_data#host"), "<unset>")
        task = deep_get(data, DictPath("event_data#task"), "<unset>")
        ansithemeprint([ANSIThemeStr("  • ", "separator"),
                        ANSIThemeStr("Task", "action"),
                        ANSIThemeStr(": ", "default"),
                        ANSIThemeStr(f"{task}", "play"),
                        ANSIThemeStr(" ", "default"),
                        ANSIThemeStr("skipped", "none"),
                        ANSIThemeStr(" on ", "default"),
                        ANSIThemeStr(f"{host}", "hostname")])
    return True


# pylint: disable-next=too-many-locals
def ansible_run_playbook(playbook: FilePath, **kwargs: Any) -> tuple[int, dict]:
    """
    Run an Ansible playbook.

        Parameters:
            playbook (FilePath): The playbook to run
            **kwargs (dict[str, Any]): Keyword arguments
                inventory (dict): An inventory dict with selection as the list of hosts to run on
                verbose (bool): Output status updates for every new Ansible event
                quiet (bool): Disable console output
                save_logs (bool | None): Override the save_logs variable in AnsibleConfiguration
        Returns:
            ((int, dict)):
                (int): The return value
                (dict): The results of the run
    """
    inventory: dict | None = deep_get(kwargs, DictPath("inventory"), None)
    verbose: bool = deep_get(kwargs, DictPath("verbose"), False)
    quiet: bool = deep_get(kwargs, DictPath("quiet"), True)
    save_logs: bool | None = deep_get(kwargs, DictPath("save_logs"))

    forks = AnsibleConfiguration.ansible_forks

    ansible_results: dict = {}

    inventories: dict | list[FilePath] = []

    if inventory is None:
        inventories = [ANSIBLE_INVENTORY]
    else:
        inventories = inventory

    start_date = datetime.now(UTC)

    event_handler = None
    if verbose:
        event_handler = __ansible_run_event_handler_verbose_cb
    elif not quiet:
        event_handler = __ansible_run_event_handler_cb

    runner = ansible_runner.interface.run(json_mode=True,
                                          quiet=True,
                                          playbook=playbook,
                                          inventory=inventories,
                                          forks=forks,
                                          event_handler=event_handler)

    retval = 0
    if runner is not None:
        for event in runner.events:
            host = deep_get(event, DictPath("event_data#host"))
            if host is None:
                continue
            retval_, d = ansible_results_extract(event)
            if not retval and retval_:
                retval = retval_
            if d:
                if host not in ansible_results:
                    ansible_results[host] = []
                ansible_results[host].append(d)
        ansible_write_log(start_date, playbook, runner.events, save_logs=save_logs)

    return retval, ansible_results
