# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
This generates and post-processes elements for various more complex types
"""

from typing import Any

# pylint: disable=line-too-long
from clustermanagementtoolkit.generators.generator_address import generator_address
from clustermanagementtoolkit.generators.generator_address_with_port import generator_address_with_port  # noqa: E501
from clustermanagementtoolkit.generators.generator_age import generator_age
from clustermanagementtoolkit.generators.generator_hex import generator_hex
from clustermanagementtoolkit.generators.generator_list import generator_list
from clustermanagementtoolkit.generators.generator_list_with_status import generator_list_with_status  # noqa: E501
from clustermanagementtoolkit.generators.generator_numerical_with_units import generator_numerical_with_units  # noqa: E501
from clustermanagementtoolkit.generators.generator_selector import generator_selector
from clustermanagementtoolkit.generators.generator_status import generator_status
from clustermanagementtoolkit.generators.generator_timestamp import generator_timestamp
from clustermanagementtoolkit.generators.generator_timestamp_with_age import generator_timestamp_with_age   # noqa: E501
from clustermanagementtoolkit.generators.generator_uri import generator_uri  # noqa: E501
from clustermanagementtoolkit.generators.generator_value_mapper import generator_value_mapper  # noqa: E501
from clustermanagementtoolkit.generators.generator_version import generator_version  # noqa: E501
# pylint: enable=line-too-long


formatter_to_generator: dict[str, dict[str, Any]] = {
    "address": {
        "generator": generator_address,
        "field_separators_default": [],
    },
    "address_with_port": {
        "generator": generator_address_with_port,
        "field_separators_default": [],
    },
    "age": {
        "generator": generator_age,
    },
    "hex": {
        "generator": generator_hex,
    },
    "list": {
        "generator": generator_list,
    },
    "list_with_status": {
        "generator": generator_list_with_status,
    },
    "numerical": {
        "generator": generator_numerical_with_units,
    },
    "selector": {
        "generator": generator_selector,
        "field_separators_default": [],
    },
    "status": {
        "generator": generator_status,
    },
    "timestamp": {
        "generator": generator_timestamp,
    },
    "timestamp_with_age": {
        "generator": generator_timestamp_with_age,
    },
    "uri": {
        "generator": generator_uri,
        "field_separators_default": [],
    },
    "value_mapper": {
        "generator": generator_value_mapper,
    },
    "version": {
        "generator": generator_version,
        "field_separators_default": [],
    },
}
