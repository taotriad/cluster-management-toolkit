# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Find the command matching a string.
"""

from collections.abc import Callable
from typing import Any

from clustermanagementtoolkit.commandparser.commandparser_types import ArgumentType
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.commandparser.commandparser_types import ArgumentWithOptionalDefaultType  # noqa: E501

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


def __find_command(d_commandline: dict[str, Any], arg: str) -> \
        tuple[str,
              Callable[[tuple[str, str], list[str]], None] | None,
              str,
              list[ArgumentType],
              list[ArgumentWithOptionalDefaultType]]:
    """
    Find the command that matches the string, if any.

        Parameters:
            d_commandline (dict[str, Any]: The command-line dict
            arg (str): The string to check for a matching command
        Returns:
            ((str, Callable, str, [dict], [dict])):
                (str): The name of the matched command; empty if no match was found
                (Callable): The callback for the matched command; None if no match was found
                (str): The matching key in the command-line dict; empty if no match was found
                ([ArgumentType]): The dict of required arguments for the command
                ([ArgumentWithOptionalDefaultType]): The dict of optional arguments for the command
    """
    callback: Callable[[tuple[str, str], list[str]], None] | None = None
    commandname: str = ""
    required_args: list[ArgumentType] = []
    optional_args: list[ArgumentWithOptionalDefaultType] = []
    key: str = ""

    for key, value in d_commandline.items():
        if key == "extended_description":
            continue

        for cmd in deep_get(value, DictPath("command"), []):
            if cmd == arg:
                commandname = cmd
                callback = deep_get(value, DictPath("callback"))
                required_args = deep_get(value, DictPath("required_args"), [])
                optional_args = deep_get(value, DictPath("optional_args"), [])
                break
        if callback is not None:
            break

    return commandname, callback, key, required_args, optional_args
