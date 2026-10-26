# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
This generates and post-processes elements for various more complex types
"""

from typing import Any

from clustermanagementtoolkit.datagetters.datagetter_api_support import datagetter_api_support
from clustermanagementtoolkit.datagetters.datagetter_pod_status import datagetter_pod_status
from clustermanagementtoolkit.generators.generator_mem import generator_mem
from clustermanagementtoolkit.generators.generator_status import generator_status

builtin_fields: dict[str, dict[str, Any]] = {
    "age": {
        "header": "Age:",
        "paths": [{
            "path": ["metadata#creationTimestamp"],
            "pathtype": "value",
            "type": "timestamp",
            "default": -1,
        }],
        "formatter": "age",
        "align": "right",
    },
    "api_support": {
        "header": "API Support:",
        "datagetter": datagetter_api_support,
        "formatter": "list",
    },
    "mem": {
        "header": "Mem% / Total:",
        "paths": [
            {
                "path": "status#allocatable#memory",
                "pathtype": "value",
                "type": "str",
            },
            {
                "path": "status#capacity#memory",
                "pathtype": "value",
                "type": "str",
            },
        ],
        "generator": generator_mem,
        "ralign": True,
    },
    "name": {
        "header": "Name:",
        "path": "metadata#name",
        "type": "str",
    },
    "namespace": {
        "header": "Namespace:",
        "path": "metadata#namespace",
        "type": "str",
        "formatting": {
            "field_colors": [
                {
                    "type": "namespace",
                },
            ],
        },
    },
    "pod_status": {
        "header": "Status:",
        "datagetter": datagetter_pod_status,
        "generator": generator_status,
    },
}
