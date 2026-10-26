# vim: ts=4 filetype=python expandtab shiftwidth=4 softtabstop=4 syntax=python
# Requires: python3 (>= 3.11)
#
# Copyright the Cluster Management Toolkit for Kubernetes contributors.
# SPDX-License-Identifier: MIT

"""
Return a list of pod resources.
"""

import concurrent.futures
from operator import itemgetter
import sys
from typing import Any

try:
    from natsort import natsorted
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("ModuleNotFoundError: Could not import natsort; "
             "you may need to (re-)run `cmt-install.py` or `pip3 install natsort`; aborting.")

from clustermanagementtoolkit import cmtlib
from clustermanagementtoolkit.cmtlib import get_since
from clustermanagementtoolkit.cmtlib import make_label_selector
from clustermanagementtoolkit.cmtlib import timestamp_to_datetime

from clustermanagementtoolkit.cmttypes import DictPath
from clustermanagementtoolkit.cmttypes import deep_get
from clustermanagementtoolkit.cmttypes import deep_get_with_fallback
from clustermanagementtoolkit.cmttypes.exceptions import ProgrammingError

from clustermanagementtoolkit.datagetters import get_container_status

from clustermanagementtoolkit.kubernetes_helper import get_node_status
from clustermanagementtoolkit.kubernetes_helper import resource_kind_to_rtype

from clustermanagementtoolkit.listgetters.get_pv_from_pvc_name import get_pv_from_pvc_name
from clustermanagementtoolkit.listgetters.get_pv_status import get_pv_status

from clustermanagementtoolkit import listgetters_async


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def get_pod_resource_list(obj: dict[str, Any], **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    """
    Return a list of resources for a pod.

        Parameters:
            obj (dict): The pod object.
            **kwargs (dict[str, Any]): Keyword arguments
                kubernetes_helper (KubernetesHelper): A reference to a KubernetesHelper object
                kh_cache (KubernetesResourceCache): A reference to a KubernetesResourceCache object
        Returns:
            (([dict[str, Any]], int)):
                ([dict[str, Any]]): The list of pod resources.
                (int): The status for the request
        Raises:
            ProgrammingError: Function called without kubernetes_helper
    """
    if (kh := deep_get(kwargs, DictPath("kubernetes_helper"))) is None:
        raise ProgrammingError(f"{__name__}() called without kubernetes_helper")
    kh_cache = deep_get(kwargs, DictPath("kh_cache"))

    vlist: list[dict[str, Any]] = []

    init_containers = True
    containers = True
    ephemeral_containers = True

    pod_name = deep_get(obj, DictPath("metadata#name"))
    pod_namespace = deep_get(obj, DictPath("metadata#namespace"))

    # We'll be one-shotting all of these, so we won't use reexecutor
    executor_ = concurrent.futures.ThreadPoolExecutor()
    executors = {}

    filter_resources = deep_get(cmtlib.cmtconfig, DictPath("Pod#filter_resources"), [])

    container_resources = []
    if init_containers:
        kind = ("InitContainer", "")
        for container in deep_get(obj, DictPath("spec#initContainers"), []):
            # We need these when iterating containers
            container_resources.append((kind, container,
                                        deep_get(obj, DictPath("status#initContainerStatuses"))))
    if containers:
        kind = ("Container", "")
        for container in deep_get(obj, DictPath("spec#containers"), []):
            # We need these when iterating containers
            container_resources.append((kind, container,
                                        deep_get(obj, DictPath("status#containerStatuses"))))
    if ephemeral_containers:
        kind = ("EphemeralContainer", "")
        for container in deep_get(obj, DictPath("spec#ephemeralContainers"), []):
            # We need these when iterating containers
            container_resources.append((kind, container,
                                        deep_get(obj,
                                                 DictPath("status#ephemeralContainerStatuses"))))

    for kind, container, container_status in container_resources:
        rtype = resource_kind_to_rtype(kind)
        ref = container
        name = deep_get(container, DictPath("name"))
        resource_tuple = ("", "", name)
        status, _status_group, restarts, message, age = \
            get_container_status(container_status, name)
        vlist.append({
            "ref": ref,
            "namespace": pod_namespace,
            "name": name,
            "kind": kind[0],
            "api_group": kind[1],
            "type": rtype,
            "resource_tuple": resource_tuple,
            "status": status,
            "restarts": restarts,
            "message": message,
            "age": age,
        })

    if "node" not in filter_resources:
        kind = ("Node", "")
        rtype = resource_kind_to_rtype(kind)
        name = deep_get(obj, DictPath("spec#nodeName"))
        ref = None
        if name is not None:
            ref = kh.get_ref_by_kind_name_namespace(("Node", ""),
                                                    name, None, resource_cache=kh_cache)
        if name is None:
            name = "<unset>"
        resource_tuple = ("", "", name)

        if ref is not None:
            status, _status_group, _taints, _full_taints = get_node_status(ref)
        else:
            status = "<unset>"

        vlist.append({
            "ref": ref,
            "namespace": pod_namespace,
            "name": name,
            "kind": kind[0],
            "api_group": kind[1],
            "type": rtype,
            "resource_tuple": resource_tuple,
            "status": status,
            "restarts": "",
            "message": "",
            "age": -1,
        })

    controller_name = ""
    controller_kind = ""

    # pylint: disable-next=too-many-nested-blocks
    for owr in deep_get(obj, DictPath("metadata#ownerReferences"), []):
        owr_kind = deep_get(owr, DictPath("kind"), "")
        owr_api_version = deep_get(owr, DictPath("apiVersion"), "")
        if "/" in owr_api_version:
            owr_api_version = owr_api_version.split("/")[0]
        else:
            owr_api_version = ""
        owr_kind = (owr_kind, owr_api_version)
        owr_name = deep_get(owr, DictPath("name"), "")
        is_controller = deep_get(owr, DictPath("controller"), False)
        if is_controller:
            controller_name = owr_name
            controller_kind = owr_kind[0]
            if "controller" in filter_resources:
                continue
            rtype = "[controller]"
        elif owr_kind == ("CronJob", "batch"):
            if "cronjob" in filter_resources:
                continue
            rtype = "[cronjob]"
        else:
            if "owner_reference" in filter_resources:
                continue
            rtype = "[owner_reference]"

        status = ""

        ref = kh.get_ref_by_kind_name_namespace(owr_kind, owr_name, pod_namespace,
                                                resource_cache=kh_cache)
        if ref is None:
            status = "<missing>"
        else:
            conditions = deep_get(ref, DictPath("status#conditions"), [])
            for condition in conditions:
                if deep_get(condition, DictPath("type"), "") == "Ready":
                    _status = deep_get(condition, DictPath("status"), "")
                    reason = deep_get(condition, DictPath("reason"), "")
                    if reason:
                        status = reason
                    else:
                        if _status == "True":
                            status = "Ready"
                        elif _status == "False":
                            status = "NotReady"
                        elif _status == "Unknown":
                            status = "Unknown"

        resource_tuple = (owr_kind[0], owr_kind[1], owr_name)
        vlist.append({
            "ref": ref,
            "namespace": pod_namespace,
            "name": owr_name,
            "kind": owr_kind[0],
            "api_group": owr_kind[1],
            "type": rtype,
            "resource_tuple": resource_tuple,
            "status": status,
            "restarts": "",
            "message": "",
            "age": -1,
        })

    if controller_kind == "Node":
        trivy_kind = "Pod"
        trivy_name = pod_name
    else:
        trivy_kind = controller_kind
        trivy_name = controller_name
    selector_dict: dict[str, str] = {
        "trivy-operator.resource.kind": trivy_kind,
        "trivy-operator.resource.name": trivy_name,
    }
    trivy_selector = make_label_selector(selector_dict)

    # OK, we have the controller kind (and thus trivy_selector);
    # time to fire off the requests for lists.
    for resource, r_kwargs in (
            ("event", {
                "kind": ("Event", ""),
                "namespace": pod_namespace,
                "field_selector": make_label_selector({
                    "involvedObject.name": pod_name,
                    "involvedObject.namespace": pod_namespace})}),
            ("pod_disruption_budget", {
                "kind": ("PodDisruptionBudget", "policy"),
                "namespace": pod_namespace}),
            ("pod_metrics", {
                "kind": ("PodMetrics", "metrics.k8s.io")}),
            ("config_audit_report", {
                "kind": ("ConfigAuditReport", "aquasecurity.github.io"),
                "namespace": pod_namespace,
                "label_selector": trivy_selector}),
            ("infra_assessment_report", {
                "kind": ("InfraAssessmentReport", "aquasecurity.github.io"),
                "namespace": pod_namespace,
                "label_selector": trivy_selector}),
            ("vulnerability_report", {
                "kind": ("VulnerabilityReport", "aquasecurity.github.io"),
                "namespace": pod_namespace,
                "label_selector": trivy_selector}),
            ("exposed_secret_report", {
                "kind": ("ExposedSecretReport", "aquasecurity.github.io"),
                "namespace": pod_namespace,
                "label_selector": trivy_selector}),
            ("sbom_report", {
                "kind": ("SbomReport", "aquasecurity.github.io"),
                "namespace": pod_namespace,
                "label_selector": trivy_selector}),
            ("antrea_agent", {
                "kind": ("AntreaAgentInfo", "crd.antrea.io")}),
            ("antrea_controller", {
                "kind": ("AntreaControllerInfo", "crd.antrea.io")}),
            ("service", {
                "kind": ("Service", ""), "namespace": pod_namespace}),
            ("resourceclaim", {
                "kind": ("ResourceClaim", "resource.k8s.io"),
                "namespace": pod_namespace})):
        kind = deep_get(r_kwargs, DictPath("kind"))
        if "kubernetes_helper" not in r_kwargs:
            r_kwargs["kubernetes_helper"] = kh
            r_kwargs["kh_cache"] = kh_cache
        if resource not in filter_resources and kh.is_kind_available(kind):
            executors[kind] = executor_.submit(listgetters_async.get_kubernetes_list, **r_kwargs)

    if "persistent_volume_claim" not in filter_resources:
        for volume in deep_get(obj, DictPath("spec#volumes"), []):
            if deep_get(volume, DictPath("persistentVolumeClaim")) is None:
                continue

            kind = ("PersistentVolume", "")
            rtype = resource_kind_to_rtype(kind)

            claim_name = deep_get(volume, DictPath("persistentVolumeClaim#claimName"))
            pv, pv_name = get_pv_from_pvc_name(claim_name, kubernetes_helper=kh)

            if pv:
                status, _status_group = get_pv_status(pv)
            else:
                pv_name = "<INVALID PV>"
                status = "Error"
            ref = pv
            resource_tuple = ("", "", pv_name)
            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": "",
                "age": -1,
            })

    if "service_account" not in filter_resources \
            and deep_get(obj, DictPath("spec#serviceAccountName")) is not None:
        kind = ("ServiceAccount", "")
        rtype = resource_kind_to_rtype(kind)

        name = deep_get(obj, DictPath("spec#serviceAccountName"))
        ref = kh.get_ref_by_kind_name_namespace(kind, name, pod_namespace, resource_cache=kh_cache)
        resource_tuple = ("", "", name)
        vlist.append({
            "ref": ref,
            "namespace": pod_namespace,
            "name": name,
            "kind": kind[0],
            "api_group": kind[1],
            "type": rtype,
            "resource_tuple": resource_tuple,
            "status": "",
            "restarts": "",
            "message": "",
            "age": -1,
        })

    for i, vol in enumerate(deep_get(obj, DictPath("spec#volumes"), [])):
        status = ""

        if deep_get(vol, DictPath("secret")) is not None and "secret" not in filter_resources:
            kind = ("Secret", "")
            rtype = resource_kind_to_rtype(kind)
            secret_name = deep_get(vol, DictPath("secret#secretName"))
            optional = deep_get(vol, DictPath("secret#optional"), False)
            resource_tuple = ("", "", secret_name)
            ref = kh.get_ref_by_kind_name_namespace(kind, secret_name, pod_namespace,
                                                    resource_cache=kh_cache)
            if ref is None:
                if not optional:
                    status = "<missing>"
                else:
                    status = "<optional>"
            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": secret_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": "",
                "age": -1,
            })

        if deep_get(vol, DictPath("configMap")) is not None \
                and "config_map" not in filter_resources:
            kind = ("ConfigMap", "")
            rtype = resource_kind_to_rtype(kind)
            cm_name = deep_get(vol, DictPath("configMap#name"))
            optional = deep_get(vol, DictPath("configMap#optional"), False)
            resource_tuple = ("", "", cm_name)
            ref = kh.get_ref_by_kind_name_namespace(kind, cm_name, pod_namespace,
                                                    resource_cache=kh_cache)
            if ref is None:
                if not optional:
                    status = "<missing>"
                else:
                    status = "<optional>"
            else:
                if not deep_get(ref, DictPath("data"), []):
                    status = "<empty>"
            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": cm_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": "",
                "age": -1,
                # We need this because multiple volumes can refer to different
                # data in the same ConfigMap.
                "metadata": {"uid": i},
            })

    if "secret" not in filter_resources:
        for vol in deep_get(obj, DictPath("spec#imagePullSecrets"), []):
            kind = ("Secret", "")
            rtype = "[image_pull_secret]"
            secret_name = deep_get(vol, DictPath("name"))
            resource_tuple = ("", "", secret_name)
            ref = kh.get_ref_by_kind_name_namespace(kind, secret_name, pod_namespace,
                                                    resource_cache=kh_cache)
            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": secret_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": "",
                "restarts": "",
                "message": "",
                "age": -1,
            })

    kind = ("PodMetrics", "metrics.k8s.io")
    if "pod_metrics" not in filter_resources and kh.is_kind_available(kind):
        podmetrics = kh.get_ref_by_kind_name_namespace(kind, pod_name, pod_namespace,
                                                       resource_cache=kh_cache)
        if podmetrics is not None and podmetrics:
            ref = podmetrics
            rtype = resource_kind_to_rtype(kind)
            resource_tuple = ("", "", pod_name)
            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": pod_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": "",
                "restarts": "",
                "message": "",
                "age": -1,
            })

    # Check if there's a matching cilium endpoint
    kind = ("CiliumEndpoint", "cilium.io")
    if "cilium_endpoint" not in filter_resources and kh.is_kind_available(kind):
        ref = kh.get_ref_by_kind_name_namespace(kind, pod_name, pod_namespace,
                                                resource_cache=kh_cache)
        if ref is not None and ref:
            rtype = resource_kind_to_rtype(kind)
            resource_tuple = ("", "", pod_name)
            status = deep_get(ref, DictPath("status#state"), "Unknown")
            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": pod_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status.capitalize(),
                "restarts": "",
                "message": "",
                "age": -1,
            })

    if "runtimeclass" not in filter_resources:
        kind = ("RuntimeClass", "node.k8s.io")
        name = deep_get(obj, DictPath("spec#runtimeClassName"))
        ref = None
        if name is not None:
            ref = kh.get_ref_by_kind_name_namespace(kind, name, "", resource_cache=kh_cache)
        if ref is not None and ref:
            rtype = resource_kind_to_rtype(kind)
            resource_tuple = ("", "", name)
            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": "",
                "restarts": "",
                "message": "",
                "age": -1,
            })

    # pylint: disable-next=too-many-nested-blocks
    for kind, ex in executors.items():
        vlist_, status_ = ex.result()
        # We ignore failures
        if status_ != 200 or not vlist_:
            continue
        rtype = resource_kind_to_rtype(kind)

        if kind == ("Event", ""):
            tmp_vlist = []
            for event in vlist_:
                ref = event
                # For kind we do not want the api_family
                event_name = deep_get(event, DictPath("metadata#name"))
                resource_tuple = (kind[0], "", event_name)
                status = deep_get(event, DictPath("type"))
                ts = deep_get_with_fallback(event, [DictPath("series#lastObservedTime"),
                                                    DictPath("deprecatedLastTimestamp"),
                                                    DictPath("lastTimestamp"),
                                                    DictPath("eventTime"),
                                                    DictPath("deprecatedFirstTimestamp"),
                                                    DictPath("firstTimestamp")])
                tmp = timestamp_to_datetime(ts)
                seen = get_since(tmp)
                message = deep_get(event, DictPath("message"), "")
                message = message.replace("\n", "\\n").rstrip()

                tmp_vlist.append({
                    "ref": ref,
                    "namespace": pod_namespace,
                    "name": event_name,
                    "kind": kind[0],
                    "api_group": kind[1],
                    "type": rtype,
                    "resource_tuple": resource_tuple,
                    "status": status,
                    "restarts": "",
                    "message": message,
                    "age": seen,
                })
            vlist += list(natsorted(tmp_vlist, key=itemgetter("age")))
            continue

        if kind == ("PodDisruptionBudget", "policy"):
            for pdb in vlist_:
                pdb_name = deep_get(pdb, DictPath("metadata#name"))
                pdb_namespace = deep_get(pdb, DictPath("metadata#namespace"))
                pdb_selector = deep_get(pdb, DictPath("spec#selector#matchLabels"), {})
                obj_labels = deep_get(obj, DictPath("metadata#labels"), {})
                # If the selector matches we're happy
                if pdb_selector.items() and obj_labels.items() != pdb_selector.items():
                    continue
                resource_tuple = ("", "", pdb_name)
                ref = pdb
                vlist.append({
                    "ref": ref,
                    "namespace": pdb_namespace,
                    "name": pdb_name,
                    "kind": kind[0],
                    "api_group": kind[1],
                    "type": rtype,
                    "resource_tuple": resource_tuple,
                    "status": "",
                    "restarts": "",
                    "message": "",
                    "age": -1,
                })
            continue

        if kind == ("ConfigAuditReport", "aquasecurity.github.io"):
            ref = vlist_[0]
            if not ref:
                continue

            report_name = deep_get(ref, DictPath("metadata#name"))

            resource_tuple = (kind[0], "", report_name)

            critical = deep_get(ref, DictPath("report#summary#criticalCount"), 0)
            high = deep_get(ref, DictPath("report#summary#highCount"), 0)
            medium = deep_get(ref, DictPath("report#summary#mediumCount"), 0)
            low = deep_get(ref, DictPath("report#summary#lowCount"), 0)

            message = ""
            message_array = []

            status = "OK"

            if low:
                status = "Warning"
                message_array.append(f"{low} Low")
            if medium:
                status = "Warning"
                message_array.insert(0, f"{medium} Medium")
            if high:
                status = "Warning"
                message_array.insert(0, f"{high} High")
            if critical:
                status = "Warning"
                message_array.insert(0, f"{critical} Critical")

            if message_array:
                message = "Reported issues: "
                message += " / ".join(message_array)

            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": pod_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": message,
                "age": -1,
            })
            continue

        if kind == ("InfraAssessmentReport", "aquasecurity.github.io"):
            ref = vlist_[0]
            if not ref:
                continue

            report_name = deep_get(ref, DictPath("metadata#name"))

            resource_tuple = (kind[0], "", report_name)

            critical = deep_get(ref, DictPath("report#summary#criticalCount"), 0)
            high = deep_get(ref, DictPath("report#summary#highCount"), 0)
            medium = deep_get(ref, DictPath("report#summary#mediumCount"), 0)
            low = deep_get(ref, DictPath("report#summary#lowCount"), 0)

            message = ""
            message_array = []

            status = "OK"

            if low:
                status = "Warning"
                message_array.append(f"{low} Low")
            if medium:
                status = "Warning"
                message_array.insert(0, f"{medium} Medium")
            if high:
                status = "Warning"
                message_array.insert(0, f"{high} High")
            if critical:
                status = "Warning"
                message_array.insert(0, f"{critical} Critical")

            if message_array:
                message = "Reported issues: "
                message += " / ".join(message_array)

            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": pod_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": message,
                "age": -1,
            })
            continue

        if kind == ("VulnerabilityReport", "aquasecurity.github.io"):
            ref = vlist_[0]
            if not ref:
                continue

            report_name = deep_get(ref, DictPath("metadata#name"))

            resource_tuple = (kind[0], "", report_name)

            critical = deep_get(ref, DictPath("report#summary#criticalCount"), 0)
            high = deep_get(ref, DictPath("report#summary#highCount"), 0)
            medium = deep_get(ref, DictPath("report#summary#mediumCount"), 0)
            unknown = deep_get(ref, DictPath("report#summary#unknownCount"), 0)
            low = deep_get(ref, DictPath("report#summary#lowCount"), 0)

            message = ""
            message_array = []

            status = "OK"

            if low:
                status = "Warning"
                message_array.append(f"{low} Low")
            if unknown:
                status = "Warning"
                message_array.insert(0, f"{unknown} Unknown")
            if medium:
                status = "Warning"
                message_array.insert(0, f"{medium} Medium")
            if high:
                status = "Warning"
                message_array.insert(0, f"{high} High")
            if critical:
                status = "Warning"
                message_array.insert(0, f"{critical} Critical")

            if message_array:
                message = "Reported issues: "
                message += " / ".join(message_array)

            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": pod_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": message,
                "age": -1,
            })
            continue

        if kind == ("ExposedSecretReport", "aquasecurity.github.io"):
            ref = vlist_[0]
            if not ref:
                continue

            report_name = deep_get(ref, DictPath("metadata#name"))

            resource_tuple = (kind[0], "", report_name)

            critical = deep_get(ref, DictPath("report#summary#criticalCount"), 0)
            high = deep_get(ref, DictPath("report#summary#highCount"), 0)
            medium = deep_get(ref, DictPath("report#summary#mediumCount"), 0)
            low = deep_get(ref, DictPath("report#summary#lowCount"), 0)

            message = ""
            message_array = []

            status = "OK"

            if low:
                status = "Warning"
                message_array.append(f"{low} Low")
            if medium:
                status = "Warning"
                message_array.insert(0, f"{medium} Medium")
            if high:
                status = "Warning"
                message_array.insert(0, f"{high} High")
            if critical:
                status = "Warning"
                message_array.insert(0, f"{critical} Critical")

            if message_array:
                message = "Reported issues: "
                message += " / ".join(message_array)

            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": pod_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": message,
                "age": -1,
            })
            continue

        if kind == ("SbomReport", "aquasecurity.github.io"):
            ref = vlist_[0]
            if not ref:
                continue

            report_name = deep_get(ref, DictPath("metadata#name"))

            resource_tuple = (kind[0], "", report_name)

            message = ""
            message_array = []

            status = ""

            if message_array:
                message = "Reported issues: "
                message += " / ".join(message_array)

            vlist.append({
                "ref": ref,
                "namespace": pod_namespace,
                "name": pod_name,
                "kind": kind[0],
                "api_group": kind[1],
                "type": rtype,
                "resource_tuple": resource_tuple,
                "status": status,
                "restarts": "",
                "message": message,
                "age": -1,
            })
            continue

        # OK, this pod is an antrea-agent, so we should look for one that matches it
        if kind == ("AntreaAgentInfo", "crd.antrea.io"):
            for item in vlist_:
                if deep_get(item, DictPath("podRef#namespace"), "") == pod_namespace \
                        and deep_get(item, DictPath("podRef#name"), "") == pod_name:
                    ref = item
                    name = deep_get(item, DictPath("metadata#name"))
                    status = "Unknown"
                    for condition in deep_get(item, DictPath("agentConditions"), {}):
                        if deep_get(condition, DictPath("type")) == "AgentHealthy":
                            healthy = deep_get(condition, DictPath("status"), "Unknown")
                            if healthy == "True":
                                status = "Healthy"
                            elif healthy == "False":
                                status = "Unhealthy"
                    resource_tuple = ("", "", name)

                    vlist.append({
                        "ref": ref,
                        "namespace": pod_namespace,
                        "name": name,
                        "kind": kind[0],
                        "api_group": kind[1],
                        "type": rtype,
                        "resource_tuple": resource_tuple,
                        "status": status,
                        "restarts": "",
                        "message": "",
                        "age": -1,
                    })
                    break
            continue

        # OK, this pod is an antrea-controller, so we should look for one that matches it
        if kind == ("AntreaControllerInfo", "crd.antrea.io"):
            for item in vlist_:
                if deep_get(item, DictPath("podRef#namespace"), "") == pod_namespace \
                        and deep_get(item, DictPath("podRef#name"), "") == pod_name:
                    ref = item
                    name = deep_get(item, DictPath("metadata#name"))
                    status = "Unknown"
                    for condition in deep_get(item, DictPath("controllerConditions"), {}):
                        if deep_get(condition, DictPath("type")) == "ControllerHealthy":
                            healthy = deep_get(condition, DictPath("status"), "Unknown")
                            if healthy == "True":
                                status = "Healthy"
                            elif healthy == "False":
                                status = "Unhealthy"
                    rtype = resource_kind_to_rtype(kind)
                    resource_tuple = ("", "", name)
                    vlist.append({
                        "ref": ref,
                        "namespace": pod_namespace,
                        "name": name,
                        "kind": kind[0],
                        "api_group": kind[1],
                        "type": rtype,
                        "resource_tuple": resource_tuple,
                        "status": status,
                        "restarts": "",
                        "message": "",
                        "age": -1,
                    })
                    break
            continue

        # Find service(s) that has a selector that points to this pod
        if kind == ("Service", ""):
            for item in vlist_:
                selector = deep_get(item, DictPath("spec#selector"), {})
                if not selector:
                    continue
                vlist2_, status = \
                    kh.get_list_by_kind_namespace(("Pod", ""), pod_namespace,
                                                  label_selector=make_label_selector(selector),
                                                  field_selector=f"metadata.name={pod_name},"
                                                                 "metadata.namespace="
                                                                 f"{pod_namespace}",
                                                  resource_cache=kh_cache)
                if vlist2_:
                    ref = item
                    name = deep_get(item, DictPath("metadata#name"))
                    namespace = deep_get(item, DictPath("metadata#namespace"))
                    resource_tuple = ("", "", name)
                    vlist.append({
                        "ref": ref,
                        "namespace": namespace,
                        "name": name,
                        "kind": kind[0],
                        "api_group": kind[1],
                        "type": rtype,
                        "resource_tuple": resource_tuple,
                        "status": "",
                        "restarts": "",
                        "message": "",
                        "age": -1,
                    })
            continue

        if kind == ("ResourceClaim", "resource.k8s.io"):
            for item in vlist_:
                owr = deep_get(item, DictPath("metadata#ownerReferences"), [])
                for owner_reference in owr:
                    if deep_get(owner_reference, DictPath("controller"), False) and \
                       deep_get(owner_reference, DictPath("kind"), "") == "Pod" and \
                       deep_get(owner_reference, DictPath("name"), "") == pod_name:
                        name = deep_get(item, DictPath("metadata#name"))
                        resource_tuple = ("", "", name)
                        vlist.append({
                            "ref": item,
                            "namespace": pod_namespace,
                            "name": name,
                            "kind": kind[0],
                            "api_group": kind[1],
                            "type": rtype,
                            "resource_tuple": resource_tuple,
                            "status": "",
                            "restarts": "",
                            "message": "",
                            "age": -1,
                        })
            continue

    return vlist, 200
