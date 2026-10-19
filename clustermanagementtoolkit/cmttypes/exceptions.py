# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Custom exceptions used by CMT.
"""

from datetime import datetime, UTC
import os
import sys
import traceback
from typing import Any

from clustermanagementtoolkit.cmttypes.deep_get import deep_get
from clustermanagementtoolkit.cmttypes.dictpath import DictPath
from clustermanagementtoolkit.cmttypes.filepath import FilePathAuditError
from clustermanagementtoolkit.cmttypes.reformat_msg import reformat_msg

__all__ = [
    "FilePathAuditError",
    "ProgrammingError",
]


# pylint: disable-next=too-many-instance-attributes
class UnknownError(Exception):
    """
    Exception raised when an error occurs that we have no further information about
    Note: severity and formatted_msg use Any as type to avoid recursive imports,
    but they are typically LogLevel and list[ANSIThemeStr], respectively.

    Optional arguments are normally deduced; overriding them is only necessary in special cases.

        Attributes:
            message (str): Additional information about the error
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
        if not self.message:
            message = "No further details were provided"
        else:
            message = self.message

        return message

    def exception_dict(self) -> dict:
        """
        Return a dictionary containing structured information about the exception.

            Returns:
                (dict): A dictionary with structured information
        """
        return {
            "exception": self.exception,
            "message": self.message,
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


# pylint: disable-next=too-many-instance-attributes
class ArgumentValidationError(Exception):
    """
    Exception raised when argument validation fails.
    Note: severity use Any as type to avoid recursive imports,
    but it is typically LogLevel.

    Optional arguments are normally deduced; overriding them is only necessary in special cases.

        Attributes:
            message (str): Additional information about the error
            subexception (Exception): Related standard exception
            severity (any): The severity
            facility (str): A facility
            formatted_msg ([[(str, str)]]); A formatted version of the message
            timestamp (datetime): A timestamp (optional)
            file (str): The file the error occurred in (optional)
            function (str): The function the error occurred in (optional)
            lineno (str): The line the error occurred on (optional)
            ppid (str): The parent pid of the process (optional)
    """
    traceback: str | None = None

    def __init__(self, **kwargs: Any) -> None:
        message: str | None = deep_get(kwargs, DictPath("message"))
        subexception: Exception | None = deep_get(kwargs, DictPath("subexception"))
        severity: Any | None = deep_get(kwargs, DictPath("severity"))
        facility: str | None = deep_get(kwargs, DictPath("facility"))
        formatted_msg: list[list[tuple[str, str]]] | None = deep_get(kwargs,
                                                                     DictPath("formatted_msg"))
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

        if message is None and formatted_msg is not None and formatted_msg:
            message = reformat_msg(formatted_msg)

        self.exception = __class__.__name__  # type: ignore
        self.subexception = subexception
        self.message = message
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
        if self.subexception is None:
            message = ""
        else:
            message = f"({self.subexception}): "

        if not self.message:
            message += "No further details were provided"
        else:
            message += f"{self.message}"

        return message

    def exception_dict(self) -> dict:
        """
        Return a dictionary containing structured information about the exception.

            Returns:
                (dict): A dictionary with structured information
        """
        return {
            "exception": self.exception,
            "subexception": self.subexception,
            "message": self.message,
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


# pylint: disable-next=too-many-instance-attributes
class ProgrammingError(Exception):
    """
    Exception raised when a condition occured that is most likely caused by a programming error
    Note: severity and formatted_msg use Any as type to avoid recursive imports,
    but they are typically LogLevel and list[ANSIThemeStr], respectively.

    Optional arguments are normally deduced; overriding them is only necessary in special cases.

        Attributes:
            message (str): Additional information about the error
            subexception (Exception): Related standard exception
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
        subexception: Exception | None = deep_get(kwargs, DictPath("subexception"))
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
        self.subexception = subexception
        self.message = message
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
        if self.subexception is None:
            message = ""
        else:
            message = f"({self.subexception}): "

        if not self.message:
            message += "No further details were provided"
        else:
            message += f"{self.message}"

        return message

    def exception_dict(self) -> dict:
        """
        Return a dictionary containing structured information about the exception.

            Returns:
                (dict): A dictionary with structured information
        """
        return {
            "exception": self.exception,
            "subexception": self.subexception,
            "message": self.message,
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
