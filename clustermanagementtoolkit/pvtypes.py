#! /usr/bin/env python3
# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Known Persistent Volume types. Note: with the introduction of CSIDrivers
most of these are deprecated.
"""

from typing import TypedDict


class PVInfoType(TypedDict):
    """
    A TypedDict for persistent volume type information.

        Parameters:
            type (str): The volume type
            description (str): A description of the volume type
            properties (dict[str, dict[str, dict | str | bool | None]]): Properties for the volume
    """
    type: str
    description: str
    properties: dict[str, dict[str, dict | str | bool | None]]


KNOWN_PV_TYPES: dict[str, PVInfoType] = {
    # Deprecated
    "awsElasticBlockStore": {
        "type": "AWS Elastic Block Storage",
        "description": "Represents a Persistent Disk resource in AWS",
        "properties": {
            "Volume ID:": {"path": "volumeID"},
            "Partition #:": {"path": "partition"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    # Deprecated
    "azureDisk": {
        "type": "Azure Disk",
        "description": "Azure Data Disk mount on the host and bind mount to the pod",
        "properties": {
            "Disk Name:": {"path": "diskName"},
            "Disk URI:": {"path": "diskURI"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Read Only:": {"path": "readOnly", "default": False},
            "Caching Mode:": {"path": "cachingMode"},
            "Kind:": {"path": "kind", "default": "shared"},
        },
    },
    # Deprecated
    "azureFile": {
        "type": "Azure File",
        "description": "Azure File Service mount on the host and bind mount to the pod",
        "properties": {
            "Share Name:": {"path": "shareName"},
            "Read Only:": {"path": "readOnly", "default": False},
            "Secret Name:": {"path": "secretName"},
            "Secret Namespace:": {"path": "secretNamespace", "default": "<pod namespace>"},
        },
    },
    # Deprecated
    "cephfs": {
        "type": "Ceph",
        "description": "CephFS mount on the host that shares a pod's lifetime",
        "properties": {
            "Path:": {"path": "path", "default": "/"},
            "Read Only:": {"path": "readOnly", "default": False},
            "Rados User": {"path": "user", "default": "admin"},
            "Secret File:": {"path": "secretFile", "default": "/etc/ceph/user.secret"},
        },
    },
    # Deprecated
    "cinder": {
        "type": "OpenStack Cinder Volume",
        "description": "Cinder volume attached and mounted on kubelets host machine",
        "properties": {
            "Volume ID:": {"path": "volumeID"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    "csi": {
        "type": "External CSI Volume",
        "description": "Storage managed by an external CSI volume driver",
        "properties": {
            "Volume Handle:": {"path": "volumeHandle"},
            "Driver:": {"path": "driver"},
            "Filesystem Type:": {"path": "fsType", "default": "<unset>"},
            "Read Only:": {"path": "readOnly", "default": False},
            "Storage Pool": {"path": "volumeAttributes#storagePool"},
        },
    },
    "fc": {
        "type": "Fibre Channel Volume",
        "description": "Fibre Channel resource that is attached "
                       "to a kubelet's host machine and then exposed to the pod",
        "properties": {
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Logical Unit Number:": {"path": "lun"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    # Deprecated
    "flexVolume": {
        "type": "FlexPersistentVolumeSource",
        "description": "Generic persistent volume "
                       "resource provisioned/attached using an exec based plugin",
        "properties": {
            "Driver:": {"path": "driver"},
            "Filesystem Type:": {"path": "fsType", "default": "<script dependent>"},
            "Read Only:": {"path": "readOnly", "default": False},
            "Options": {"path": "options", "default": {}},
        },
    },
    # Deprecated
    "flocker": {
        "type": "Flocker Volume",
        "description": "Flocker Volume mounted by the Flocker agent",
        "properties": {
            "Dataset Name:": {"path": "datasetName"},
            "Dataset UUID:": {"path": "datasetUUID"},
        },
    },
    # Deprecated
    "gcePersistentDisk": {
        "type": "GCE Persistent Disk",
        "description": "Google Compute Engine Persistent Disk resource",
        "properties": {
            "PD Name:": {"path": "pdName"},
            "Partition:": {"path": "partition"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    # Deprecated
    "glusterfs": {
        "type": "GlusterFS",
        "description": "Glusterfs mount that lasts the lifetime of a pod",
        "properties": {
            "Path:": {"path": "path"},
            "Endpoints:": {"path": "endpoints"},
            "Endpoints Namespace:": {"path": "endpoints", "default": "<PVC namespace>"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    "hostPath": {
        # Only works in single-node clusters
        "type": "Host Path",
        "description": "Host path mapped into a pod",
        "properties": {
            "Path:": {"path": "path"},
            "Host Path Type:": {"path": "type", "default": ""},
        },
    },
    "iscsi": {
        "type": "iSCSI Disk",
        "description": "ISCSI Disk resource that is attached "
                       "to a kubelet's host machine and then exposed to the pod",
        "properties": {
            "iSCSI Qualified Name:": {"path": "iqn"},
            "Logical Unit Number:": {"path": "lun"},
            "Target Portal:": {"path": "targetPortal"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Chap Auth Discovery:": {"path": "chapAuthDiscovery"},
            "Chap Auth Session:": {"path": "chapAuthSession"},
            "iSCSI Initiator:": {"path": "initiatorName"},
            "iSCSI Interface:": {"path": "iscsiInterface", "default": "tcp"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    "local": {
        "type": "Local",
        "description": "Directly-attached storage with node affinity",
        "properties": {
            "Path:": {"path": "path"},
            "Filesystem Type:": {"path": "fsType", "default": "<auto-detect>"},
        },
    },
    "nfs": {
        "type": "NFS",
        "description": "NFS mount that lasts the lifetime of a pod",
        "properties": {
            "Server:": {"path": "server"},
            "Path:": {"path": "path"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    # Deprecated
    "portworxVolume": {
        "type": "Portworx volume",
        "description": "Portworx volume attached and mounted on kubelets host machine",
        "properties": {
            "Volume ID:": {"path": "volumeID"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Read Only:": {"path": "readOnly", "default": False},
        },
    },
    # Deprecated
    "quobyte": {
        "type": "Quobyte Mount",
        "description": "Quobyte mount that lasts the lifetime of a pod",
        "properties": {
            "Volume Name:": {"path": "volume"},
            "Read Only:": {"path": "readOnly", "default": False},
            "Tenant:": {"path": "tenant"},
            "User:": {"path": "user", "default": "<service account user>"},
            "Group:": {"path": "group", "default": None},
        },
    },
    # Deprecated
    "rbd": {
        "type": "RBD",
        "description": "Rados Block Device mount that lasts the lifetime of a pod",
        "properties": {
            "Image:": {"path": "image"},
            "Pool:": {"path": "pool", "default": "rbd"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Read Only:": {"path": "readOnly"},
            "Rados User": {"path": "user", "default": "admin"},
            "Keyring:": {"path": "keyring", "default": "/etc/ceph/keyring"},
        },
    },
    # Deprecated
    "scaleIO": {
        "type": "Persistent ScaleIO Volume",
        "description": "ScaleIO persistent volume attached and mounted on Kubernetes nodes",
        "properties": {
            "Volume Name:": {"path": "volumeName"},
            "Gateway:": {"path": "gateway"},
            "Storage Pool:": {"path": "storagePool"},
            "Storage System:": {"path": "system"},
            "Storage Mode:": {"path": "storageMode", "default": "ThinProvisioned"},
            "Filesystem Type:": {"path": "fsType", "default": "xfs"},
            "Protection Domain:": {"path": "protectionDomain"},
            "SSL Enabled:": {"path": "sslEnabled", "default": False},
            "Read Only:": {"path": "readOnly"},
        },
    },
    # Deprecated
    "storageos": {
        "type": "Persistent StorageOS Volume",
        "description": "StorageOS volume that is attached "
                       "to the kubelet's host machine and mounted into the pod",
        "properties": {
            "Volume Name:": {"path": "volumeName"},
            "Volume Namespace:": {"path": "volumeNamespace", "default": "<pod namespace>"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Read Only:": {"path": "readOnly"},
        },
    },
    # Deprecated
    "vsphereVolume": {
        "type": "vSphere Volume",
        "description": "vSphere volume attached and mounted on kubelets host machine",
        "properties": {
            "Volume Path:": {"path": "volumePath"},
            "Filesystem Type:": {"path": "fsType", "default": "ext4"},
            "Storage Policy ID:": {"path": "storagePolicyID"},
            "Storage Policy Name:": {"path": "storagePolicyName"},
        },
    },
}
