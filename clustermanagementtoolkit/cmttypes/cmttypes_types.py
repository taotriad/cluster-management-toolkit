# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Various types used by CMT.
"""

from enum import auto, Enum, IntEnum


class HostNameStatus(Enum):
    """
    Return values from validate_hostname().
    """
    OK = auto()
    DNS_SUBDOMAIN_EMPTY = auto()
    DNS_SUBDOMAIN_TOO_LONG = auto()
    DNS_SUBDOMAIN_WRONG_CASE = auto()
    DNS_SUBDOMAIN_INVALID_FORMAT = auto()
    DNS_LABEL_STARTS_WITH_IDNA = auto()
    DNS_LABEL_INVALID_FORMAT = auto()
    DNS_LABEL_TOO_LONG = auto()
    DNS_LABEL_PUNYCODE_TOO_LONG = auto()
    DNS_LABEL_INVALID_CHARACTERS = auto()
    DNS_TLD_INVALID = auto()


class LogLevel(IntEnum):
    """
    Loglevels used by CMT.

    LogLevel.ALL will be substituted by LogLevel.DEBUG unless it's overriden,
    since it's intended to show all log data.
    """
    EMERG = 0
    ALERT = 1
    CRIT = 2
    ERR = 3
    WARNING = 4
    NOTICE = 5
    NOTE = 5
    INFO = 6
    SYSTEM = 6
    DEBUG = 7
    VERBOSE = 7
    DIFFPLUS = 8
    DIFFMINUS = 9
    DIFFSAME = 10
    DEFAULT = 254
    ALL = 255


class SecurityChecks(Enum):
    """
    Checks that can be performed by check_path().
    """
    PARENT_RESOLVES_TO_SELF = auto()
    RESOLVES_TO_SELF = auto()
    OWNER_IN_ALLOWLIST = auto()
    PARENT_OWNER_IN_ALLOWLIST = auto()
    PERMISSIONS = auto()
    PARENT_PERMISSIONS = auto()
    CAN_READ_IF_EXISTS = auto()
    EXISTS = auto()
    IS_FILE = auto()
    IS_DIR = auto()
    IS_SYMLINK = auto()
    IS_EXECUTABLE = auto()
    IS_NOT_EXECUTABLE = auto()


class SecurityPolicy(Enum):
    """
    Security policies used by CMT.
    """
    # Only allows exact matches
    STRICT = auto()
    # Only allows exact matches from any path in the allowlist
    ALLOWLIST_STRICT = auto()
    # Allows exact matches from any path in the allowlist,
    # but path elements can be symlinks
    ALLOWLIST_RELAXED = auto()


class SecurityStatus(IntEnum):
    """
    Return values from check_path().
    """
    OK = auto()
    # Critical
    PERMISSIONS = auto()
    PARENT_PERMISSIONS = auto()
    OWNER_NOT_IN_ALLOWLIST = auto()
    PARENT_OWNER_NOT_IN_ALLOWLIST = auto()
    PATH_NOT_RESOLVING_TO_SELF = auto()
    PARENT_PATH_NOT_RESOLVING_TO_SELF = auto()
    # Error
    DOES_NOT_EXIST = auto()
    PARENT_DOES_NOT_EXIST = auto()
    IS_NOT_FILE = auto()
    IS_NOT_DIR = auto()
    IS_NOT_SYMLINK = auto()
    IS_EXECUTABLE = auto()
    IS_NOT_EXECUTABLE = auto()
    PARENT_IS_NOT_DIR = auto()
    DIR_NOT_EMPTY = auto()
    EXISTS = auto()


loglevel_mappings: dict[LogLevel, str] = {
    LogLevel.EMERG: "Emergency",
    LogLevel.ALERT: "Alert",
    LogLevel.CRIT: "Critical",
    LogLevel.ERR: "Error",
    LogLevel.WARNING: "Warning",
    LogLevel.NOTICE: "Notice",
    LogLevel.NOTE: "Notice",
    LogLevel.INFO: "Info",
    LogLevel.SYSTEM: "Info",
    LogLevel.DEFAULT: "Info",
    LogLevel.DEBUG: "Debug",
    LogLevel.VERBOSE: "Debug",
    LogLevel.DIFFPLUS: "Diffplus",
    LogLevel.DIFFMINUS: "Diffminus",
    LogLevel.DIFFSAME: "Diffsame",
    LogLevel.ALL: "Debug",
}


class Retval(Enum):
    """
    Return values from the UI functions.
    """
    NOMATCH = 0     # No keypress matched/processed; further checks needed (if any)
    MATCH = 1       # keypress matched/processed; no further action
    RETURNONE = 2   # keypress matched/processed; return up one level
    RETURNFULL = 3  # keypress matched/processed, callback called; return up entire callstack
    RETURNDONE = 4  # We've done our Return One


class StatusGroup(IntEnum):
    """
    Status groups used by CMT.
    """
    NEUTRAL = 8
    DONE = 7
    OK = 6
    PENDING = 5
    WARNING = 4
    ADMIN = 3
    NOT_OK = 2
    UNKNOWN = 1
    CRIT = 0


stgroup_mapping = {
    StatusGroup.CRIT: "status_critical",
    StatusGroup.UNKNOWN: "status_unknown",
    StatusGroup.NOT_OK: "status_not_ok",
    StatusGroup.ADMIN: "status_admin",
    StatusGroup.WARNING: "status_warning",
    StatusGroup.OK: "status_ok",
    StatusGroup.PENDING: "status_pending",
    StatusGroup.DONE: "status_done",
}
