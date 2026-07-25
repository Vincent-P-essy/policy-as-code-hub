# METADATA
# title: Workload helpers
# description: |
#   Extracts containers and pod specs from any Kubernetes workload kind, so a
#   policy is written once instead of once per kind.
#
#   Every policy in this repository goes through these helpers. A policy that
#   walks `input.spec.containers` directly works on a bare Pod and silently
#   passes every Deployment, StatefulSet, DaemonSet, Job and CronJob in the
#   cluster - which is the failure mode that makes a policy library dangerous
#   rather than merely incomplete.
package lib.workload

import rego.v1

# The pod spec, wherever this kind happens to keep it.
pod_spec := input.spec.template.spec if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
}

pod_spec := input.spec.jobTemplate.spec.template.spec if {
	input.kind == "CronJob"
}

pod_spec := input.spec if {
	input.kind == "Pod"
}

# Every container, including init and ephemeral ones. An init container runs
# with the same privileges and is a common way to smuggle one past review.
containers contains container if {
	some container in object.get(pod_spec, "containers", [])
}

containers contains container if {
	some container in object.get(pod_spec, "initContainers", [])
}

containers contains container if {
	some container in object.get(pod_spec, "ephemeralContainers", [])
}

# The effective security context: pod-level defaults, overridden by the
# container's own. Reading only the pod level reports a hardened workload whose
# containers each override it back.
security_context(container) := object.union(
	object.get(pod_spec, "securityContext", {}),
	object.get(container, "securityContext", {}),
)

is_workload if {
	input.kind in {
		"Pod", "Deployment", "StatefulSet", "DaemonSet",
		"ReplicaSet", "Job", "CronJob",
	}
}

name := object.get(input, ["metadata", "name"], "unnamed")
