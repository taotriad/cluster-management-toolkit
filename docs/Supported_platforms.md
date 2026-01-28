# Supported platforms

## Platform support (cluster installation)

| Functionality: | Distribution:            | Version:        |
| :------------- | :----------------------- | :-------------- |
| kubeadm/RKE2   | Debian                   | 12+             |
| kubeadm/RKE2   | Ubuntu                   | 24.04+          |
| kubeadm/RKE2   | Ubuntu Server            | 24.04+          |
| kubeadm        | Red Hat Enterprise Linux | 8+              |
| kubeadm/RKE2   | SUSE Enterprise Linux    | SLES 15.6+*     |
| kubeadm/RKE2   | openSUSE                 | openSUSE 15.6+* |

## What platforms are used for development and testing

All main development takes place on Debian Unstable. Some testing
is also performed on RHEL 9 (mainly using Code Ready Containers),
openSUSE 16 (RKE2 + Rancher), and Ubuntu 24.04 LTS.

## What prevents __CMT__ from being support on other Distributions / Older versions

In most cases it's simply because it hasn't been tested on those distributions or versions,
or because the required version of Python is too old.

__CMT__ is written in Python3 and requires version 3.11 or newer.
This rules out installer & tool support for Debian 11 (Python 3.7).

On openSUSE/SLES 15 and RHEL 8 you should be able to install python311
and python311-pip or newer to get a recent version of Python3.
You also need to specify `ansible_python_interpreter: <path to python>`
in the Ansible inventory for such hosts, since Ansible playbooks
will fail to run otherwise.

## Limitations

* CRI-O is currently not supported as CRI on Red Hat-based distros.
* Upgrading is not supported on SUSE-based distros.
