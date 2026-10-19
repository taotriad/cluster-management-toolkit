# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Custom type classes used by generators.
"""

from typing import Any, TypedDict

from clustermanagementtoolkit.curses_helper import ThemeAttr
from clustermanagementtoolkit.curses_helper import ThemeRef


class RangeType(TypedDict):
    """
    A dict with range mapping information.

        Parameters:
            min (None | int | float): The start of the range (None for an open-started range)
            max (None | int | float): The end of the range (None for an open-ended range)
            field_colors ([ThemeAttr]): The colors to apply to matching values (length: 1)
            default (bool): Is this the default range?
    """
    min: int | float | None
    max: int | float | None
    field_colors: list[ThemeAttr]
    default: bool


class MappingTypeOptional(TypedDict, total=False):
    """
    Optional parts of a dict with mapping information.

        Parameters:
            substitutions (dict[int | str, str | dict | ThemeRef]): Substitutions to perform
            ranges ([RangeType]): Range mapping information
            match_case (bool): Should mapping be case sensitive?
            mappings (dict): A dict of mappings
    """
    substitutions: dict[int | str, str | dict | ThemeRef]
    ranges: list[RangeType]
    match_case: bool
    mappings: dict[Any, dict[str, list[dict[str, str]]]]


class MappingType(MappingTypeOptional):
    """
    A dict with mapping information.
    """


class FormattingTypeOptional(TypedDict, total=False):
    """
    Optional parts of a dict with formatting information.

        Parameters:
            item_separator (ThemeRef): The separator to use between items in a list
            field_separators ([ThemeRef]): The separators to use between members in a field
            field_colors ([ThemeAttr]): The colors to use for each member in a field
            ellipsise (int): Ellipsise after this many list entries (-1 to keep the entire list)
            ellipsis (ThemeRef): The string to use to ellipsise a list
            field_prefixes ([[ThemeRef]]): The prefix(es) for each member in a field
            field_suffixes ([[ThemeRef]]): The suffix(es) for each member in a field
            mapping (MappingType): A dict with information about value mappings
            field_formatters ([str]): A list of formatters to apply to each field in a list
    """
    item_separator: ThemeRef
    field_separators: list[ThemeRef]
    field_colors: list[ThemeAttr]
    ellipsise: int
    ellipsis: ThemeRef
    field_prefixes: list[list[ThemeRef]]
    field_suffixes: list[list[ThemeRef]]
    args: dict[str, dict[str, Any]]
    mapping: dict[str, MappingType]
    field_formatters: list[str]


class FormattingType(FormattingTypeOptional):
    """
    A dict with formatting information.
    """
