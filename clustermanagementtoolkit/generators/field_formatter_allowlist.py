# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Allowlist for field-formatters.
"""

from collections.abc import Callable

from clustermanagementtoolkit.generators.format_address import format_address
from clustermanagementtoolkit.generators.format_address_with_port import format_address_with_port
# pylint: disable-next=line-too-long
from clustermanagementtoolkit.generators.format_numerical_with_units import format_numerical_with_units  # noqa: E501
from clustermanagementtoolkit.generators.format_selector import format_selector
from clustermanagementtoolkit.generators.format_uri import format_uri
from clustermanagementtoolkit.generators.format_version import format_version

# Formatters acceptable for use with list fields.
field_formatter_allowlist: dict[str, Callable] = {
    "address": format_address,
    "address_with_port": format_address_with_port,
    "numerical_with_units": format_numerical_with_units,
    "selector": format_selector,
    "uri": format_uri,
    "version": format_version,
}
