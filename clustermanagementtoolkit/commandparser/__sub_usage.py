# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Display usage information for a single command.
"""

import errno
import sys

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint import themearray_len

from clustermanagementtoolkit.commandparser import commandparser_types

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get


# pylint: disable-next=too-many-locals,too-many-branches
def __sub_usage(command: str) -> int:
    """
    Display usage information for a single command.
    TODO: We need to support options for __sub_usage, to handle --format.

        Parameters:
            command (str): The command to show help for
        Returns:
            (int): 0
    """
    commandinfo = {}
    headerstring: list[ANSIThemeStr] = []
    command_found = False

    for value in commandparser_types.commandline.values():
        if command in deep_get(value, DictPath("command"), {}):
            commandstring = deep_get(value, DictPath("command_alias"), command)
            headerstring = [ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                            ANSIThemeStr(f" {commandstring}", "command")]
            commandinfo = value
            command_found = True
            break

    if not command_found:
        ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                        ANSIThemeStr(": unrecognised command “", "default"),
                        ANSIThemeStr(f"{command}", "command"),
                        ANSIThemeStr("“.", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("Try “", "default"),
                        ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                        ANSIThemeStr("help", "command"),
                        ANSIThemeStr("“ for more information.", "default")], stderr=True)
        sys.exit(errno.EINVAL)

    values = deep_get(commandinfo, DictPath("values"), [])
    options = deep_get(commandinfo, DictPath("options"), [])
    description = deep_get(commandinfo, DictPath("description"), [])
    extended_description = deep_get(commandinfo, DictPath("extended_description"), [])

    if not description and not extended_description:
        ansithemeprint([ANSIThemeStr("Error", "warning"),
                        ANSIThemeStr(": Could not find help entry for command "
                                     f"{command}; aborting.", "default")], stderr=True)
        sys.exit(errno.ENOENT)

    if options:
        headerstring += [ANSIThemeStr(" [", "separator"),
                         ANSIThemeStr("OPTION", "option"),
                         ANSIThemeStr("]", "separator"),
                         ANSIThemeStr("...", "option")]
    if values:
        headerstring += [ANSIThemeStr(" ", "separator")] + values

    ansithemeprint(headerstring)
    print()
    ansithemeprint(description)
    print()
    if extended_description:
        for line in extended_description:
            ansithemeprint([ANSIThemeStr("  ", "description")] + line)
        print()

    if options:
        max_optionlen = 0
        for option, optiondata in options.items():
            optionlen = len(option) + 4 + themearray_len(deep_get(optiondata,
                                                                  DictPath("values"), ""))
            max_optionlen = max(max_optionlen, optionlen)

        ansithemeprint([ANSIThemeStr("Options:", "description")])
        for option, optiondata in options.items():
            optionline = [ANSIThemeStr(f"  {option}", "option")]
            values = deep_get(optiondata, DictPath("values"), [])
            description = deep_get(optiondata, DictPath("description"), [])
            extended_description = deep_get(optiondata, DictPath("extended_description"), [])

            if values:
                optionline += [ANSIThemeStr(" ", "option")] + values
            pad = " ".rjust(max_optionlen - themearray_len(optionline))
            optionline += [ANSIThemeStr(pad, "description")] + description
            ansithemeprint(optionline)

            pad = " ".rjust(max_optionlen)
            for extended_line in extended_description:
                ansithemeprint([ANSIThemeStr(pad, "description")] + extended_line)

    return 0
