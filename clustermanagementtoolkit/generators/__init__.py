# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
This generates and post-processes elements for various more complex types
"""

# pylint: disable=line-too-long
from clustermanagementtoolkit.generators.align_and_pad import align_and_pad
from clustermanagementtoolkit.generators.fieldgenerator import fieldgenerator
from clustermanagementtoolkit.generators.format_address import format_address
from clustermanagementtoolkit.generators.format_list import format_list
from clustermanagementtoolkit.generators.format_numerical_with_units import format_numerical_with_units  # noqa: E501
from clustermanagementtoolkit.generators.format_special import format_special
from clustermanagementtoolkit.generators.format_timestamp import format_timestamp
from clustermanagementtoolkit.generators.format_uri import format_uri
from clustermanagementtoolkit.generators.format_version import format_version
from clustermanagementtoolkit.generators.generator_address import generator_address
from clustermanagementtoolkit.generators.generator_basic import generator_basic
from clustermanagementtoolkit.generators.generator_value_mapper import generator_value_mapper
from clustermanagementtoolkit.generators.get_formatter import get_formatter
from clustermanagementtoolkit.generators.get_formatting import get_formatting
from clustermanagementtoolkit.generators.generators_types import FormattingType
from clustermanagementtoolkit.generators.map_value import map_value
# pylint: enable=line-too-long

__all__ = [
    "FormattingType",
    "align_and_pad",
    "fieldgenerator",
    "format_address",
    "format_list",
    "format_numerical_with_units",
    "format_special",
    "format_timestamp",
    "format_uri",
    "format_version",
    "generator_address",
    "generator_basic",
    "generator_value_mapper",
    "get_formatter",
    "get_formatting",
    "map_value",
]
