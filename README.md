# Cluster Management Toolkit for Kubernetes

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8263/badge)](https://www.bestpractices.dev/projects/11639)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/taotriad/cluster-management-toolkit/badge)](https://securityscorecards.dev/viewer/?uri=github.com/taotriad/cluster-management-toolkit)
[![Known Vulnerabilities](https://snyk.io/test/github/taotriad/cluster-management-toolkit/badge.svg)](https://snyk.io/test/github/taotriad/cluster-management-toolkit)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/taotriad/cluster-management-toolkit/main)
![GitHub commits since latest release](https://img.shields.io/github/commits-since/taotriad/cluster-management-toolkit/latest)

![CMT Logo](docs/images/cmt_logo.png 'CMT Logo')

----

__Cluster Management Toolkit for Kubernetes__ (CMT) is a set of tools intended
to simplify installation and maintenance of _Kubernetes_ clusters. It provides
tools to setup clusters and manage nodes, either by specifying the configuration
directly on the command line, or through template files.

The _curses_-based user interface (_cmu_) presents the various Kubernetes
objects (such as Pods, Deployments, ConfigMaps, Namespaces, etc.) in a way that
tries to obviate all object relations. This includes both direct relatations
such as those defined in ownerReferences, selectors, and volume mounts,
but also nested relations, such as from Pods directly to a CronJob or Deployment.

The UI also tries its best to improve the viewing experience for the data;
the Kubernetes objects themselves can be viewed as either JSON or YAML,
many of the ConfigMaps in text format can be viewed with syntax highlighting,
and base64-encoded text-documents can be decoded before they're viewed.

Finally container logs are parsed (sometimes in a rather opinionated manner),
restructed, and highlighted based on the severity of the messages.
Structures can be unfolded, repeating lines can be deduplicated,
debug messages and traces are hidden by default, etc.

Currently a bit over 800 object types are supporting to varying levels,
250 different pod log files are defined (most of them matching multiple signatures),
and 40+ ConfigMap data types.

The inventory tool, _cmtinv_, allows for managing the Ansible inventory,
but also running of playbooks.

Installation and management is done through a combination of _Ansible_ playbooks,
_Python_ scripts, a _curses_-based user interface, as well as calls to _kubectl_
or _kubeadm_ whenever necessary.

Usage documentation for CMT is available [here](docs/README.md).
