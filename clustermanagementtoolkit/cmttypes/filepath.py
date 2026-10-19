# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A custom type used for file paths, with file operations.
"""

from datetime import datetime, UTC
import os
from pathlib import Path, PurePath
import sys
import traceback
from typing import Any, Union

from clustermanagementtoolkit.cmttypes.deep_get import deep_get
from clustermanagementtoolkit.cmttypes.dictpath import DictPath


class FilePath(str):
    """
    A wrapper used for paths, to ensure correct types.
    """

    # We need to use Union here since we have a forward declaration.
    def __init__(self, path: Union["FilePath", str, Path, PurePath]) -> None:
        self.path = str(path)

    def __str__(self) -> str:
        return self.path

    def basename(self) -> str:
        """
        Returns the filename part of the FilePath.

            Returns:
                (str): The filename path of the FilePath.
        """
        return os.path.basename(self.path)

    def dirname(self) -> "FilePath":
        """
        Returns the dirname part of the FilePath.

            Returns:
                (FilePath): The dirname path of the FilePath.
        """
        return FilePath(os.path.dirname(self.path))

    def joinpath(self, *paths: Any) -> "FilePath":
        """
        Perform a path join on a FilePath
        with either a PurePath, a str, a FilePath,
        a list of strings, or a tuple of strings.

            Parameters:
                paths (str|FilePath|PurePath|list|tuple): The path(s) to append
            Returns:
                (FilePath): The new FilePath
            Raises:
                FilePathAuditError: At least one of the subpaths started with a path separator
                TypeError: paths was an unsupported type
        """
        # If any of the path elements start with "/" we regard it as an attempt
        # to do path-based attacks. It seems that PurePath(path).joinpath("/")
        # does not handle joining strings starting with a path separator in a safe manner,
        # so we better implement the check ourselves.
        if (subpath := next((s for s in paths if str(s).startswith(os.path.sep)), "")):
            raise FilePathAuditError("Subpath contains path separator", path=subpath)

        # PurePath will raise TypeError if an element
        # in the list/tuple isn't a string
        return FilePath(PurePath(self.path).joinpath(*paths))


# pylint: disable-next=too-many-instance-attributes
class FilePathAuditError(Exception):
    """
    Exception raised when a security check fails on a FilePath
    Note: severity and formatted_msg use Any as type to avoid recursive imports,
    but they are typically LogLevel and list[ANSIThemeStr], respectively.

    Optional arguments are normally deduced; overriding them is only necessary in special cases.

        Attributes:
            message (str): Additional information about the error
            path (FilePath): The path being audited
            severity (any): The severity
            facility (str): A facility
            formatted_msg (any); A formatted version of the message
            timestamp (datetime): A timestamp (optional)
            file (str): The file the error occurred in (optional)
            function (str): The function the error occurred in (optional)
            lineno (str): The line the error occurred on (optional)
            ppid (str): The parent pid of the process (optional)
    """
    traceback: str | None = None

    def __init__(self, message: str, **kwargs: Any) -> None:
        path: FilePath | None = deep_get(kwargs, DictPath("path"))
        severity: Any | None = deep_get(kwargs, DictPath("severity"))
        facility: str | None = deep_get(kwargs, DictPath("facility"))
        formatted_msg: Any | None = deep_get(kwargs, DictPath("formatted_msg"))
        timestamp: datetime | None = deep_get(kwargs, DictPath("timestamp"))
        file: str | None = deep_get(kwargs, DictPath("file"))
        function: str | None = deep_get(kwargs, DictPath("function"))
        lineno: int | None = deep_get(kwargs, DictPath("lineno"))
        ppid: int | None = deep_get(kwargs, DictPath("ppid"))
        try:
            # This is to get the necessary stack info
            raise UserWarning
        except UserWarning:
            frame = sys.exc_info()[2].tb_frame.f_back  # type: ignore
            self.file = str(frame.f_code.co_filename)  # type: ignore
            self.function = str(frame.f_code.co_name)  # type: ignore
            self.lineno = int(frame.f_lineno)  # type: ignore

        self.exception = __class__.__name__  # type: ignore
        self.message = message
        self.path = path
        self.severity = severity
        self.facility = facility
        self.formatted_msg = formatted_msg
        if timestamp is None:
            self.timestamp = datetime.now(UTC)
        else:
            self.timestamp = timestamp
        if file is not None:
            self.file = file
        if function is not None:
            self.function = function
        if lineno is not None:
            self.lineno = lineno
        if ppid is not None:
            self.ppid = ppid
        else:
            self.ppid = os.getppid()
        self.traceback = "".join(traceback.format_stack())

        super().__init__(message)

    def __str__(self) -> str:
        """
        Return a string representation of the exception.

            Returns:
                (str): The string representation of the exception
        """
        if self.path is None:
            path = "<omitted>"
        else:
            path = self.path
        if not self.message:
            message = "No further details were provided"
        else:
            message = self.message

        msg = f"Security policy violation for path {path}.  {message}"

        return msg

    def exception_dict(self) -> dict:
        """
        Return a dictionary containing structured information about the exception.

            Returns:
                (dict): A dictionary with structured information
        """
        return {
            "exception": self.exception,
            "message": self.message,
            "path": self.path,
            "severity": self.severity,
            "facility": self.facility,
            "formatted_msg": self.formatted_msg,
            "timestamp": self.timestamp,
            "file": self.file,
            "function": self.function,
            "lineno": self.lineno,
            "ppid": self.ppid,
            "traceback": self.traceback,
        }
