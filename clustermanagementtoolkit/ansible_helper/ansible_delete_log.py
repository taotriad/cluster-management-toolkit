# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from typing import Any
from pathlib import Path

from clustermanagementtoolkit.cmtio import secure_rm, secure_rmdir

from clustermanagementtoolkit.cmtpaths import ANSIBLE_LOGS_DIR

from clustermanagementtoolkit.cmttypes import DictPath, FilePath
from clustermanagementtoolkit.cmttypes import deep_get


def ansible_delete_log(log: str, **kwargs: Any) -> None:
    """
    Delete a log file.
    FIXME: This should be moved elsewhere since it's used by other components
    than just Ansible logs.

        Parameters:
            log (str): The name of the log to delete
            **kwargs (dict[str, Any]): Keyword arguments
                dirpath (str): The path to the logs
    """
    dirpath: str = deep_get(kwargs, DictPath("dirpath"), ANSIBLE_LOGS_DIR)
    logpath: Path = Path(f"{dirpath}/{log}")
    if logpath.exists():
        if logpath.is_dir():
            for file in logpath.iterdir():
                secure_rm(FilePath(file))
            secure_rmdir(FilePath(logpath))
        else:
            secure_rm(FilePath(logpath))
