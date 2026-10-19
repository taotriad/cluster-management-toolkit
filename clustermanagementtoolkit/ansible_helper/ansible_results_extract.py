# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.ansible_helper.ansible_extract_failure import ansible_extract_failure


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def ansible_results_extract(event: dict) -> tuple[int, dict]:
    """
    Extract a result from an Ansible play.

        Parameters:
            event (dict): The output from the run
        Returns:
            ((int, dict)):
                (int): 0 on success, -1 if host is unreachable, retval on other failure
                (dict): A dict
    """
    retval_: int | None = -1

    # Special events
    if deep_get(event, DictPath("event"), "") == "playbook_on_no_hosts_matched":
        d: dict = {
            "task": "",
            "start_date": "",
            "end_date": "",
            "retval": retval_,
            "no_hosts_matched": True,
            "unreachable": False,
            "status": "NO HOSTS MATCHED",
            "skipped": False,
            "stdout_lines": [],
            "stderr_lines": [],
            "msg_lines": [],
            "ansible_facts": {},
        }
        return -1, d

    if not deep_get(event, DictPath("event_data#host"), ""):
        return 0, {}

    if not (task := deep_get(event, DictPath("event_data#task"), "")):
        return 0, {}

    ansible_facts = deep_get(event, DictPath("event_data#res#ansible_facts"), {})

    skipped = deep_get(event, DictPath("event"), "") == "runner_on_skipped"
    failed = deep_get(event, DictPath("event"), "") == "runner_on_failed"
    unreachable = deep_get(event, DictPath("event_data#res#unreachable"), False)

    if unreachable:
        retval_ = -1
    elif skipped or deep_get(event, DictPath("event"), "") == "runner_on_ok":
        retval_ = 0
    elif failed:
        retval_ = -1
    else:
        retval_ = deep_get(event, DictPath("event_data#res#rc"))

    if task.startswith("hide_on_ok: "):
        if not retval_:
            retval_ = None
        else:
            task = task.removeprefix("hide_on_ok: ")
    elif task == "Gathering Facts" and not retval_:
        retval_ = None

    if retval_ is None:
        return 0, {}

    msg = deep_get(event, DictPath("event_data#res#msg"), "")
    msg_lines = []
    if msg:
        msg_lines = msg.split("\n")

    start_date_timestamp = deep_get(event, DictPath("event_data#start"))
    end_date_timestamp = deep_get(event, DictPath("event_data#end"))

    stdout = deep_get(event, DictPath("event_data#res#stdout"), "")
    stderr = deep_get(event, DictPath("event_data#res#stderr"), "")
    stdout_lines = deep_get(event, DictPath("event_data#res#stdout_lines"), [])
    stderr_lines = deep_get(event, DictPath("event_data#res#stderr_lines"), [])

    if not stdout_lines and stdout:
        stdout_lines = stdout.split("\n")
    if not stderr_lines and stderr:
        stderr_lines = stderr.split("\n")

    d = {
        "task": task,
        "start_date": start_date_timestamp,
        "end_date": end_date_timestamp,
        "retval": retval_,
        "no_hosts_matched": False,
        "unreachable": unreachable,
        "status": "UNKNOWN",
        "skipped": skipped,
        "stdout_lines": [],
        "stderr_lines": [],
        "msg_lines": [],
        "ansible_facts": ansible_facts,
    }

    if not unreachable and not retval_:
        d["status"] = "SUCCESS"

    if msg_lines or stdout_lines or stderr_lines:
        if stdout_lines:
            d["stdout_lines"] = stdout_lines
        if stderr_lines:
            d["stderr_lines"] = stderr_lines
        # We do not want msg unless both stdout_lines and stderr_lines are empty.
        if not stdout_lines and not stderr_lines and msg_lines:
            if retval_:
                d["stderr_lines"] = msg_lines
            else:
                d["msg_lines"] = msg_lines
    else:
        d["stdout_lines"] = ["<no output>"]

    error_msg_lines = stderr_lines
    if not error_msg_lines:
        error_msg_lines = msg_lines
    d["status"] = ansible_extract_failure(retval_, error_msg_lines,
                                          skipped=skipped, unreachable=unreachable)

    return retval_, d
