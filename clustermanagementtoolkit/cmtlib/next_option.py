# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

def next_option(current: str, options: list[str], wraparound: bool = True) -> str:
    """
    Given a list of options, and the currently selected option,
    return the next entry in the list, by default with wraparound.
    If current does not exist in the list, or if list is empty, current is returned.
    Note: Since this function uses index() it does not support duplicate entries.

        Parameters:
            current (str): The current option
            options ([str]): The possible options
            wraparound (bool): True to wrap around to the first option whenn
                               reaching the end of the list; False to stay at the last entry
        Returns:
            (str): The new option
    """
    new_current: str = current

    try:
        if wraparound:
            new_current = options[(options.index(current) + 1) % len(options)]
        else:
            new_current = options[min(options.index(current) + 1, len(options) - 1)]
    except ValueError:
        pass

    return new_current
