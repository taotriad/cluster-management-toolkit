# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Types used by the command line parser.
"""

from collections.abc import Callable
from typing import Any, TypedDict

from clustermanagementtoolkit.ansithemeprint import ANSIThemeStr


class ValidationTypeOptional(TypedDict, total=False):
    """
    Optional fields in the TypedDict for argument validation.

        Parameters:
            allowlist ([str]): A list of explicitly allowed values used by the allowlist validator
            regex (str): A regular expression used by the regex validator
            list_separator (str): A separator to use to split the argument into a list
            valid_range (([int | None, int | None])): A range of valid values
    """
    allowlist: list[str]
    regex: str
    list_separator: str
    valid_range: tuple[int | None, int | None]


class ValidationType(ValidationTypeOptional):
    """
    A TypedDict for argument validation.

        Parameters:
            validator (str): The name of the validator to use
    """
    validator: str


class ArgumentWithDefaultType(TypedDict, total=False):
    """
    Argument TypedDict to use when a default argument can be valid.

        Parameters:
            default (str): The default value for an argument
    """
    default: str


class ArgumentWithOptionalDefaultType(ArgumentWithDefaultType):
    """
    Argument TypedDict to use with optional default argument; to be used
    when the argument is optional, since mandatory arguments cannot have a default.

        Parameters:
            name (str)   # The name of the argument
            string ([ANSIThemeStr]): An ANSIThemeArray with a description of the argument
            validation (ValidationType): Information about validation to perform on the argument
    """
    name: str
    string: list[ANSIThemeStr]
    validation: ValidationType


class ArgumentType(TypedDict):
    """
    The TypedDict for use with required arguments.

        Parameters:
            name (str)   # The name of the argument
            string ([ANSIThemeStr]): An ANSIThemeArray with a description of the argument
            validation  (ValidationType): Information about validation to perform on the argument
    """
    name: str
    string: list[ANSIThemeStr]
    validation: ValidationType


class OptionTypeOptional(TypedDict, total=False):
    """
    Optional fields that are part of the TypedDict for options.

        Parameters:
            extended_description ([[ANSIThemeStr]]): A multi-line description of the option
            requires_arg (bool): Does the option require an argument?
            values  ([ANSIThemeStr]): An ANSIThemeArray with ARGUMENTs to the option
            validation (ValidationType): Information about validation to perform on the argument
    """
    extended_description: list[list[ANSIThemeStr]]
    requires_arg: bool
    values: list[ANSIThemeStr]
    validation: ValidationType
    hidden: bool


class OptionType(OptionTypeOptional):
    """
    A TypedDict for options.

        Parameters:
            description ([ANSIThemeStr]): A description of the option
    """
    description: list[ANSIThemeStr]


class CommandTypeOptional(TypedDict, total=False):
    """
    Optional fields for the TypedDict for commands.

        Parameters:
            command_alias (str): A string with an alias for the command
            values ([ANSIThemeStr]): An ANSIThemeArray with ARGUMENTs to the command
            options (dict[str, Optional[OptionType]]): A dict of command options
            implicit_options: ([(str, Any)]): A list of implicit options
            extended_description ([[ANSIThemeStr]]): A multi-line description of the command
    """
    command_alias: str
    values: list[ANSIThemeStr]
    options: dict[str, OptionType]
    implicit_options: list[tuple[str, Any]]
    extended_description: list[list[ANSIThemeStr]]


class CommandType(CommandTypeOptional):
    """
    A TypedDict for commands.

        Parameters:
            command ([str]): A list of command aliases
            description ([ANSIThemeStr]): An ANSIThemeArray with a description of the command
            required_args ([ArgumentType]): A list of required arguments
            optional_args ([ArgumentWithOptionalDefaultType]): A list of optional arguments
            callback (Callable | None): The callback to use
    """
    command: list[str]
    description: list[ANSIThemeStr]
    required_args: list[ArgumentType]
    optional_args: list[ArgumentWithOptionalDefaultType]
    callback: Callable | None


# Global definitions
programname: str = ""  # pylint: disable=invalid-name
programversion: str = ""  # pylint: disable=invalid-name
programdescription: str = ""  # pylint: disable=invalid-name
programauthors: str = ""  # pylint: disable=invalid-name
commandline: dict[str, Any] = {}
