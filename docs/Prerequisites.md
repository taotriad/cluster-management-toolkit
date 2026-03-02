# Pre-requisites / tested platforms for the toolkit

The installer, `cmt-install` has only been tested on Debian, Ubuntu, Raspberry Pi OS,
openSUSE/SLES, and Red Hat Enterprise Linux.

If the dependencies are installed manually, any distro or self-compiled
system that provides recent enough versions of all pre-requisites should be expected to work.
Windows is not supported at the moment, and is unlikely to work even
if all dependencies are been provided manually, due to differences
in path lookup and various I/O-operations.

macOS support will be added when a suitable development system is availble.
With today's memory prices even a Mac Mini is too expensive to buy for the singular
purpose of just adding macOS support.

## Dependencies for the toolkit (from `requirements.txt`)

* `python3-ansible-runner` (>= 2.1.4)
* `setuptools` (>= 78.1.1; this is not a direct dependency, this is to ensure that a security issue in ansible-runner is fixed)
* `python3-jinja2` (>= 3.1.6)
* `python3-natsort` (>= 8.0.2)
* `python3-prctl` (not a strict necessity, recommended for cleaner ps output)
* `python3-ruyaml` _or_ `python3-ruamel.yaml` (ruyaml seems to be more actively maintained, but either is fine)
* `python3-ujson` (>= 5.4.0; not a strict necessity, just a nice performance improvement)
* `python3-urllib3` (>= 2.6.3)
* `python3-validators` (>= 0.22.0)
* `python3-yaml` (>= 6.0)

# Pre-requisites / tested platforms for setting up Kubernetes clusters

The development platforms for __CMT__ are Debian and Ubuntu, and those two are thus the most tested platforms.
__CMT__ support for openSUSE/SLES, RHEL8, and Fedora systems has also been added, but the support for those platforms
are is tested and may have limitations. Notably _CRI-O_ is currently not supported on RHEL8 (and has not been tested
on RHEL9).

Other distributions are not supported at this point. This also applies to Windows.

# A note on firewalls

`firewalld` and other firewall software prevent
Kubernetes from working _in their default configuration_. It is possible to configure firewalls
to allow the required ports, but such configuration is, at least currently, out of scope for
this documentation.  `cmtadm` and `cmt` currently do *NOT* disable firewalls during installation.
If you have issues you will either have to look up online how to configure the firewall to work
with Kubernetes (recommended) or, if the setup is purely for internal use, disable the firewall
completely (*not recommended*).

# Supported hardware architectures

_CMT_ has been tested to work on _x86-64_/_amd64_ (many different systems) and on _arm64_ (Raspberry Pi 5).
No tests have been made on _ppc64le_, and _s390x_, but as long as the required dependencies
are available there are no reasons for it not to work. Feel free to report success/failure.

# Other pre-requisites

`cmt-install`, `cmtadm`, `cmt`, and `cmu` require the user to have _sudo_ access.
For security reasons none of the programs can be run directly as root.
The user also needs _sudo_ access on any remote system intended for use as control planes or worker nodes in a cluster.

# TERM setting support for `cmu`

`cmu` is implemented using the terminal UI toolkit `curses`
and requires support for at least 8 colors (preferably 16) and UTF-8 character support,
as well as various composite keys, such as F-keys, page up/down, home/end, shift+home/shift+end,
shift+left/shift+right, etc.  This means that several common TERM settings are unsupported.

## TERM settings known to work

* `xterm`
* `xterm-256color`
* `screen`
* `tmux`
* `tmux-256color`
* `gnome`
* `gnome-256color`
* `konsole`
* `konsole-256color`

## TERM settings known NOT to work

* `linux` (composite key issues)
* `vt100` (`has_colors()` returns false)
* `ansi` (composite key issues, UTF-8 not supported)
* `rxvt` (composite key issues)
