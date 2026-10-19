# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Parse a command-line.
"""

from collections.abc import Callable
import errno
import sys
from typing import Any, cast

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr
from clustermanagementtoolkit.ansithemeprint import ansithemeprint
from clustermanagementtoolkit.ansithemeprint import init_ansithemeprint

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import FilePath
from clustermanagementtoolkit.cmttypes import deep_get

from clustermanagementtoolkit import cmtvalidators

from clustermanagementtoolkit.commandparser.__command_usage import __command_usage
from clustermanagementtoolkit.commandparser.__find_command import __find_command
from clustermanagementtoolkit.commandparser.__sub_usage import __sub_usage
from clustermanagementtoolkit.commandparser.__usage import __usage
from clustermanagementtoolkit.commandparser.__version import __version
from clustermanagementtoolkit.commandparser import commandparser_types
from clustermanagementtoolkit.commandparser.commandparser_types import ArgumentType
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.commandparser.commandparser_types import ArgumentWithOptionalDefaultType  # noqa: E501
from clustermanagementtoolkit.commandparser.commandparser_types import CommandType


COMMANDLINEDEFAULTS: dict[str, CommandType] = {
    "Help": {
        "command": ["help"],
        "values": [ANSIThemeStr("COMMAND", "argument")],
        "description": [ANSIThemeStr("Display help about ", "description"),
                        ANSIThemeStr("COMMAND", "argument"),
                        ANSIThemeStr(" and exit", "description")],
        "options": {
            "--debug": {
                "values": [],
                "description": [],
                "hidden": True,
            },
            "--format": {
                "values": [],
                "description": [],
                "requires_arg": True,
                "validation": {
                    "validator": "allowlist",
                    "allowlist": ["default", "markdown", "short"],
                },
                "hidden": True,
            },
        },
        "required_args": [],
        "optional_args": [
            {
                "name": "command",
                "string": [
                    ANSIThemeStr("COMMAND", "argument")],
                "validation": {
                    "validator": "regex",
                    "regex": r"^[a-z][a-z0-9-]*$",
                },
            },
        ],
        "callback": __command_usage,
    },
    "Help2": {
        "command": ["help", "--help"],
        "description": [ANSIThemeStr("Display this help and exit", "description")],
        "options": {
            "--format": {
                "values": [ANSIThemeStr("FORMAT", "argument")],
                "description": [ANSIThemeStr("Output the help as ", "description"),
                                ANSIThemeStr("FORMAT", "argument"),
                                ANSIThemeStr(" instead", "description")],
                "extended_description": [
                    [ANSIThemeStr("Valid formats are:", "description")],
                    [ANSIThemeStr("default", "argument"),
                     ANSIThemeStr(", ", "separator"),
                     ANSIThemeStr("short", "argument"),
                     ANSIThemeStr(", ", "separator"),
                     ANSIThemeStr("markdown", "argument")],
                ],
                "requires_arg": True,
                "validation": {
                    "validator": "allowlist",
                    "allowlist": ["default", "markdown", "short"],
                },
            },
        },
        "required_args": [],
        "optional_args": [],
        "callback": __usage,
    },
    "Version": {
        "command": ["version", "--version"],
        "description": [ANSIThemeStr("Output version information and exit", "description")],
        "required_args": [],
        "optional_args": [],
        "callback": __version,
    },
}


# noqa: E501 pylint: disable-next=too-many-locals,too-many-branches,too-many-statements,too-many-arguments,too-many-positional-arguments
def parse_commandline(p_programname: str, p_programversion: str,
                      p_programdescription: str, p_programauthors: str,
                      argv: list[str], p_commandline: dict[str, Any],
                      **kwargs: Any) -> tuple[Callable, list[tuple[str, str]], list[str]]:
    """
    Parse the command line.

        Parameters:
            p_programname (str): The name of the program
                                 (used in usage and version information, and in error messages)
            p_programversion (str): The version of the program (used in version information)
            p_programdescription (str): The description of the program (used in usage information)
            p_programauthors (str): The authors of the program (used in version information)
            argv ([str]): The command line from sys.argv
            p_commandline (dict): The command line struct
            **kwargs (dict[str, Any]): Keyword arguments
                default_command (str): The command to run if none was provided
                theme (FilePath): The theme to use
        Returns:
            (Callable, [(str, str)], [str]):
                (Callable): The command to call
                ([(str, str)]): The options to pass to the command
                ([str]): The arguments to pass to the command
    """
    default_command: str | None = deep_get(kwargs, DictPath("default_command"))
    theme: FilePath | None = deep_get(kwargs, DictPath("theme"))

    i: int = 1

    commandparser_types.programname = p_programname
    cmtvalidators.set_programname(commandparser_types.programname)
    commandparser_types.programversion = p_programversion
    commandparser_types.programdescription = p_programdescription
    commandparser_types.programauthors = p_programauthors

    commandparser_types.commandline = {**p_commandline, **COMMANDLINEDEFAULTS}

    if theme is not None:
        init_ansithemeprint(theme)

    commandname = ""
    command = None
    key = None
    required_args: list[ArgumentType] = []
    optional_args: list[ArgumentWithOptionalDefaultType] = []

    options: list[tuple[str, str]] = []
    args: list[str] = []
    min_args = 0
    max_args = 0

    # pylint: disable-next=too-many-nested-blocks
    while i < len(argv):
        if "\x00" in argv[i]:
            ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                            ANSIThemeStr(": argument “", "default"),
                            ANSIThemeStr(argv[i].replace("\x00", "<NUL>"), "command"),
                            ANSIThemeStr("“ contains NUL-bytes (replaced here);\n", "default"),
                            ANSIThemeStr("this is either a programming error, a system error, "
                                         "file or memory corruption, ", "default"),
                            ANSIThemeStr("or a deliberate attempt to bypass "
                                         "security; aborting.", "default")], stderr=True)
            sys.exit(errno.EINVAL)

        # Have we got a command to execute?
        if command is None:
            commandname, command, key, required_args, optional_args = \
                __find_command(commandparser_types.commandline, argv[i])

            if command is None:
                if default_command is not None:
                    commandname, command, key, required_args, optional_args = \
                        __find_command(commandparser_types.commandline, default_command)
                elif "__*" in commandparser_types.commandline:
                    commandname, command, key, required_args, optional_args = \
                        __find_command(commandparser_types.commandline, "*")

                if command is None:
                    ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}",
                                                 "programname"),
                                    ANSIThemeStr(": unrecognised command “", "default"),
                                    ANSIThemeStr(f"{argv[i]}", "command"),
                                    ANSIThemeStr("“.", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr("Try “", "default"),
                                    ANSIThemeStr(f"{commandparser_types.programname} ",
                                                 "programname"),
                                    ANSIThemeStr("help", "command"),
                                    ANSIThemeStr("“ for more information.", "default")],
                                   stderr=True)
                    sys.exit(errno.EINVAL)

                # If we defaulted we do not want to consume any options
                continue
        # OK, we have a command, time to check for options
        elif argv[i].startswith("-"):
            # All commands except [--]help and [--]version have their own help pages
            if argv[i] == "--help" and \
                    commandname not in ("--help", "help", "--version", "version") and \
                    not commandname.startswith("__"):
                __sub_usage(commandname)
                sys.exit()

            if args:
                # I came here to have an argument, but this is an option!
                ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                                ANSIThemeStr(": option “", "default"),
                                ANSIThemeStr(f"{argv[i]}", "option"),
                                ANSIThemeStr("“ found after arguments.", "default")],
                               stderr=True)
                ansithemeprint([ANSIThemeStr("Try “", "default"),
                                ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                                ANSIThemeStr("help", "command"),
                                ANSIThemeStr("“ for more information.", "default")],
                               stderr=True)
                sys.exit(errno.EINVAL)
            else:
                # Is this option valid for this command?
                match = None
                __key = key
                for opt in deep_get(commandparser_types.commandline,
                                    DictPath(f"{__key}#options"), {}):
                    if isinstance(argv[i], str) and argv[i] == opt:
                        match = opt
                        break
                # Check global options.
                if match is None:
                    for opt in deep_get(commandparser_types.commandline,
                                        DictPath("__global_options#options"), {}):
                        if isinstance(argv[i], str) and argv[i] == opt:
                            __key = "__global_options"
                            match = opt
                            break

                if match is None:
                    ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}",
                                                 "programname"),
                                    ANSIThemeStr(": “", "default"),
                                    ANSIThemeStr(f"{commandname}", "command"),
                                    ANSIThemeStr("“ does not support option “", "default"),
                                    ANSIThemeStr(f"{argv[i]}", "option"),
                                    ANSIThemeStr("“.", "default")], stderr=True)
                    ansithemeprint([ANSIThemeStr("Try “", "default"),
                                    ANSIThemeStr(f"{commandparser_types.programname} ",
                                                 "programname"),
                                    ANSIThemeStr("help", "command"),
                                    ANSIThemeStr("“ for more information.", "default")],
                                   stderr=True)
                    sys.exit(errno.EINVAL)
                else:
                    arg: str = ""
                    option: str = match

                    # Does this option require arguments?
                    requires_arg = deep_get(commandparser_types.commandline,
                                            DictPath(f"{__key}#options#{option}#requires_arg"),
                                            False)

                    if requires_arg:
                        i += 1
                        if i >= len(argv):
                            ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}",
                                                         "programname"),
                                            ANSIThemeStr(": “", "default"),
                                            ANSIThemeStr(f"{option}", "option"),
                                            ANSIThemeStr("“ requires an argument.", "default")],
                                           stderr=True)
                            ansithemeprint([ANSIThemeStr("Try “", "default"),
                                            ANSIThemeStr(f"{commandparser_types.programname} ",
                                                         "programname"),
                                            ANSIThemeStr("help", "command"),
                                            ANSIThemeStr("“ for more information.", "default")],
                                           stderr=True)
                            sys.exit(errno.EINVAL)
                        arg = argv[i]

                        # Validate the option argument
                        validator_options = \
                            deep_get(commandparser_types.commandline,
                                     DictPath(f"{__key}#options#{option}#validation"), {})

                        # validate_argument() will terminate by default if validation fails
                        _result = \
                            cmtvalidators.validate_argument(arg,
                                                            [ANSIThemeStr(f"{option}", "option")],
                                                            validator_options)
                    options.append((option, arg))
        else:
            args.append(argv[i])
        i += 1

    if command is None and default_command is not None:
        commandname, command, key, required_args, optional_args = \
            __find_command(commandparser_types.commandline, default_command)

    min_args = len(required_args)
    max_args = min_args + len(optional_args)

    if not max_args and args:
        ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                        ANSIThemeStr(": “", "default"),
                        ANSIThemeStr(f"{commandname}", "command"),
                        ANSIThemeStr("“ does not accept arguments.", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("Try “", "default"),
                        ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                        ANSIThemeStr("help", "command"),
                        ANSIThemeStr("“ for more information.", "default")], stderr=True)
        sys.exit(errno.EINVAL)
    elif len(args) < min_args and min_args != max_args:
        ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                        ANSIThemeStr(": “", "default"),
                        ANSIThemeStr(f"{commandname}", "command"),
                        ANSIThemeStr(f"“ requires at least {min_args} arguments.", "default")],
                       stderr=True)
        ansithemeprint([ANSIThemeStr("Try “", "default"),
                        ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                        ANSIThemeStr("help", "command"),
                        ANSIThemeStr("“ for more information.", "default")], stderr=True)
        sys.exit(errno.EINVAL)
    elif len(args) != min_args and min_args == max_args:
        ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                        ANSIThemeStr(": “", "default"),
                        ANSIThemeStr(f"{commandname}", "command"),
                        ANSIThemeStr(f"“ requires exactly {min_args} arguments.", "default")],
                       stderr=True)
        ansithemeprint([ANSIThemeStr("Try “", "default"),
                        ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                        ANSIThemeStr("help", "command"),
                        ANSIThemeStr("“ for more information.", "default")], stderr=True)
        sys.exit(errno.EINVAL)
    elif len(args) > max_args:
        ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                        ANSIThemeStr(": “", "default"),
                        ANSIThemeStr(f"{commandname}", "command"),
                        ANSIThemeStr(f"“ requires at most {max_args} arguments.", "default")],
                       stderr=True)
        ansithemeprint([ANSIThemeStr("Try “", "default"),
                        ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                        ANSIThemeStr("help", "command"),
                        ANSIThemeStr("“ for more information.", "default")], stderr=True)
        sys.exit(errno.EINVAL)

    # The command was called without any command and no default was defined; this is an error
    if command is None:
        ansithemeprint([ANSIThemeStr(f"{commandparser_types.programname}", "programname"),
                        ANSIThemeStr(": missing operand.", "default")], stderr=True)
        ansithemeprint([ANSIThemeStr("Try “", "default"),
                        ANSIThemeStr(f"{commandparser_types.programname} ", "programname"),
                        ANSIThemeStr("help", "command"),
                        ANSIThemeStr("“ for more information.", "default")],
                       stderr=True)
        sys.exit(errno.EINVAL)
    else:
        # Are there implicit options?
        options += deep_get(commandparser_types.commandline,
                            DictPath(f"{key}#implicit_options"), [])

    # Validate the args against required_args and optional_args
    for i, argdict in enumerate(cast(list[dict], required_args) + cast(list[dict], optional_args)):
        if i >= len(args):
            break

        # Validate the argument
        validator_options = deep_get(argdict, DictPath("validation"), {})

        # validate_argument() will terminate by default if validation fails
        _result = cmtvalidators.validate_argument(args[i], argdict["string"], validator_options)

    options.append(("__commandname", commandname))

    return command, options, args
