# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Read the logparser configuration from cmtconfig.
"""

from clustermanagementtoolkit import cmtlib

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit.logparser.logparser_types import LogparserConfiguration
from clustermanagementtoolkit.logparser.logparser_types import logparser_configkeys


def init_logparser_configuration() -> None:
    """
    Read logparser configurations from cmtconfig.
    """
    for key, data in logparser_configkeys.items():
        default = deep_get(data, DictPath("default"))
        configkey = deep_get(data, DictPath("key"))
        setattr(LogparserConfiguration, key, deep_get(cmtlib.cmtconfig, configkey, default))
