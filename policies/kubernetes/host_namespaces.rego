# METADATA
# title: Workloads must not share host namespaces
# description: |
#   hostPID lets the container see and signal every process on the node,
#   including reading their memory. hostNetwork bypasses NetworkPolicy entirely
#   and binds node ports directly. hostIPC exposes shared memory to every other
#   workload using it.
# custom:
#   id: K8S-002
#   severity: critical
#   remediation: Remove hostPID, hostIPC and hostNetwork. If a workload genuinely needs node-level visibility, isolate it on a dedicated node pool.
#   frameworks:
#     cis-kubernetes: ["5.2.2", "5.2.3", "5.2.4"]
#     nist-800-53: ["SC-7", "AC-6"]
#     pci-dss-4: ["1.3.1", "2.2.4"]
package kubernetes.host_namespaces

import data.lib.workload
import rego.v1

_namespaces := {
	"hostPID": "see and signal every process on the node",
	"hostIPC": "read shared memory belonging to other workloads",
	"hostNetwork": "bypass NetworkPolicy and bind node ports directly",
}

deny contains msg if {
	workload.is_workload
	some field, consequence in _namespaces
	object.get(workload.pod_spec, field, false) == true
	msg := sprintf(
		"%s/%s: %s lets the pod %s",
		[input.kind, workload.name, field, consequence],
	)
}
