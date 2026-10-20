# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
A helper that converts a 3-letter month string to its index.
"""

def month_to_numerical(month: str) -> str:
    """
    Convert a 3-letter month string to a numerical month string.

        Parameters:
            month (str): The month string
        Returns:
            (str): The numerical value for the month
    """
    months = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
    return f"{months.index(month.lower()[0:3]):02}"
