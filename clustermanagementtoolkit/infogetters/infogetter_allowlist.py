# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

from collections.abc import Callable

from clustermanagementtoolkit.infogetters.generic_infogetter import generic_infogetter
from clustermanagementtoolkit.infogetters.get_auth_rule_info import get_auth_rule_info
from clustermanagementtoolkit.infogetters.get_cmt_log import get_cmt_log
from clustermanagementtoolkit.infogetters.get_container_info import get_container_info
from clustermanagementtoolkit.infogetters.get_eps_subsets_info import get_eps_subsets_info
from clustermanagementtoolkit.infogetters.get_journalctl_log import get_journalctl_log
from clustermanagementtoolkit.infogetters.get_key_value_info import get_key_value_info
from clustermanagementtoolkit.infogetters.get_limit_info import get_limit_info
from clustermanagementtoolkit.infogetters.get_log_info import get_log_info
from clustermanagementtoolkit.infogetters.get_promrules_info import get_promrules_info
from clustermanagementtoolkit.infogetters.get_rq_item_info import get_rq_item_info
from clustermanagementtoolkit.infogetters.get_sas_info import get_sas_info
from clustermanagementtoolkit.infogetters.get_strategy_info import get_strategy_info
from clustermanagementtoolkit.infogetters.get_subsets_info import get_subsets_info
from clustermanagementtoolkit.infogetters.get_task_log import get_task_log
from clustermanagementtoolkit.infogetters.get_themearrays import get_themearrays
from clustermanagementtoolkit.infogetters.get_traceflow import get_traceflow
from clustermanagementtoolkit.infogetters.logpad_files import logpad_files
from clustermanagementtoolkit.infogetters.logpad_formatted import logpad_formatted
from clustermanagementtoolkit.infogetters.logpad_msg_getter import logpad_msg_getter

# Infogetters acceptable for direct use in view files
infogetter_allowlist: dict[str, Callable] = {
    # Used by listview, infopad, and listpad
    "generic_infogetter": generic_infogetter,
    # Used by listview
    "get_container_info": get_container_info,
    "get_log_info": get_log_info,
    # Used by listpad
    "get_auth_rule_info": get_auth_rule_info,
    "get_eps_subsets_info": get_eps_subsets_info,
    "get_key_value_info": get_key_value_info,
    "get_limit_info": get_limit_info,
    "get_promrules_info": get_promrules_info,
    "get_rq_item_info": get_rq_item_info,
    "get_sas_info": get_sas_info,
    "get_strategy_info": get_strategy_info,
    "get_subsets_info": get_subsets_info,
    # Used by logpad
    "logpad_formatted": logpad_formatted,
    # XXX: We should aim to replace this with logpad_formatted
    "logpad_msg_getter": logpad_msg_getter,
    "logpad_files": logpad_files,
    "get_journalctl_log": get_journalctl_log,
    "get_task_log": get_task_log,
    "get_cmt_log": get_cmt_log,
    "get_themearrays": get_themearrays,
    "get_traceflow": get_traceflow,
}
