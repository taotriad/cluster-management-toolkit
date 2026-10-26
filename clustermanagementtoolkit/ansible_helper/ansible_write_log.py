# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Save an Ansible log entry to a file.
"""

from datetime import datetime
from pathlib import PurePath
import re
from typing import Any

from clustermanagementtoolkit.ansible_helper.ansible_extract_failure import ansible_extract_failure
from clustermanagementtoolkit.ansible_helper.ansible_helper_types import AnsibleConfiguration

from clustermanagementtoolkit.cmtio import secure_mkdir

from clustermanagementtoolkit.cmtio_yaml import secure_write_yaml

from clustermanagementtoolkit.cmtpaths import ANSIBLE_LOGS_DIR

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def ansible_write_log(start_date: datetime, playbook: FilePath, events: list[dict],
                      **kwargs: Any) -> None:
    """
    Save an Ansible log entry to a file.

        Parameters:
            start_date (date): A timestamp in the format YYYY-MM-DD_HH:MM:SS.ssssss
            playbook (str): The name of the playbook
            events ([dict]): The list of Ansible runs
            **kwargs (dict[str, Any]): Keyword arguments
                save_logs (bool | None): Override the save_logs variable in AnsibleConfiguration
    """
    save_logs: bool | None = deep_get(kwargs, DictPath("save_logs"))
    if save_logs is None:
        save_logs = getattr(AnsibleConfiguration, "save_logs", False)

    if not save_logs:
        return

    playbook_name = str(playbook)
    if "/" in playbook_name:
        tmp2 = str(PurePath(playbook_name).name)
        if (re_tmp := re.match(r"^(.*)\.ya?ml$", tmp2)) is not None:
            playbook_name = re_tmp[1]

    directory_name = f"{start_date}_{playbook_name}".replace(" ", "_")
    secure_mkdir(FilePath(f"{ANSIBLE_LOGS_DIR}/{directory_name}"), exit_on_failure=True)

    # Start by creating a file with metadata about the whole run
    d = {
        "playbook_path": str(playbook),
        "created_at": start_date,
    }

    metadata_path = FilePath(f"{ANSIBLE_LOGS_DIR}/{directory_name}/metadata.yaml")
    secure_write_yaml(metadata_path, d, permissions=0o600, sort_keys=False)

    i = 0

    for event in events:
        host = deep_get(event, DictPath("event_data#host"), "")
        if not host:
            continue

        task = deep_get(event, DictPath("event_data#task"), "")
        if not task:
            continue

        skipped = deep_get(event, DictPath("event"), "") == "runner_on_skipped"
        unreachable = deep_get(event, DictPath("event_data#res#unreachable"), False)

        if unreachable:
            retval = -1
        elif skipped or deep_get(event, DictPath("event"), "") == "runner_on_ok":
            retval = 0
        else:
            retval = deep_get(event, DictPath("event_data#res#rc"))

        if retval is None:
            continue

        taskname = task
        i += 1

        filename = f"{i:02d}-{host}_{taskname}.yaml".replace(" ", "_").replace("/", "_")
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

        error_msg_lines = stderr_lines
        if not error_msg_lines:
            error_msg_lines = msg_lines
        status = ansible_extract_failure(retval,
                                         error_msg_lines,
                                         skipped=skipped, unreachable=unreachable)

        d = {
            "playbook": playbook_name,
            "playbook_file": str(playbook),
            "task": task,
            "host": host,
            "start_date": start_date_timestamp,
            "end_date": end_date_timestamp,
            "retval": retval,
            "no_hosts_matched": False,
            "unreachable": unreachable,
            "skipped": skipped,
            "status": status,
        }

        if msg_lines or stdout_lines or stderr_lines:
            if stdout_lines:
                d["stdout_lines"] = stdout_lines
            if stderr_lines:
                d["stderr_lines"] = stderr_lines
            # We do not want msg unless both stdout_lines and stderr_lines are empty.
            if not stdout_lines and not stderr_lines and msg_lines:
                if retval:
                    d["stderr_lines"] = msg_lines
                else:
                    d["msg_lines"] = msg_lines
        else:
            d["stdout_lines"] = ["<no output>"]

        logentry_path = FilePath(f"{ANSIBLE_LOGS_DIR}/{directory_name}/{filename}")
        secure_write_yaml(logentry_path, d, permissions=0o600, sort_keys=False)
