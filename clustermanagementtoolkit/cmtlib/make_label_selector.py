# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def make_label_selector(selector_dict: dict) -> str:
    """
    Given a label selector dict entry, create a selector list string.

        Parameters:
            selector_dict (dict): The dict with selectors
        Returns:
            selector_str (str): The selector string
    """
    selectors = []

    if selector_dict is not None:
        for key, value in selector_dict.items():
            selectors.append(f"{key}={value}")

    return ",".join(selectors)
