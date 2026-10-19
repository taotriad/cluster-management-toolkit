# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Get the CRIO version.
"""

from clustermanagementtoolkit.networkio import get_github_version


def get_crio_version(kubernetes_version: tuple[int, int]) -> tuple[str, str] | None:
    """
    Given a Kubernetes version, return the matching cri-o version.

        Parameters:
            kubernetes_version ((int, int)): A version tuple (major, minor)
        Returns:
            (str, str): The cri-o version (major, minor)
    """
    # cri-o is built/distributed using OBS, hence we need to know the major.minor version
    # Apparently cri-o tries to keep more or less in lock-step with Kubernetes, so don't jump ahead,
    # and if Kubernetes gets ahead, use whatever is the most recent version of cri-o
    requested_major, requested_minor = kubernetes_version

    if (tmp := get_github_version("https://api.github.com/repos/cri-o/cri-o/releases",
                                  r"^v(\d+)\.(\d+)\.\d+$")) is None:
        return None

    version_tmp, _release_date, _body = tmp
    if requested_major < int(version_tmp[0]) \
            or requested_major == int(version_tmp[0]) and requested_minor < int(version_tmp[1]):
        crio_major_version = str(requested_major)
        crio_minor_version = str(requested_minor)
    else:
        crio_major_version = version_tmp[0]
        crio_minor_version = version_tmp[1]

    return crio_major_version, crio_minor_version
