# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return the version of a container image.
"""


def get_image_version(image: str, default: str = "<undefined>") -> str:
    """
    Given the version of a container image, return its version.

        Parameters:
            image (str): The name of the image
            default (str): The string to return if extracting the image version fails
        Returns:
            image_version (str): The extracted image version
    """
    image_version = image.split("@")[0]
    image_version = image_version.split("/")[-1]
    image_version = image_version.split(":")[-1]

    # If we did not manage to do any splitting it means there was not a version;
    # return default instead
    if image_version == image:
        image_version = default
    return image_version
