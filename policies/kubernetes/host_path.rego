# METADATA
# title: Sensitive host paths must not be mounted
# description: |
#   A hostPath volume punches a hole straight through the container boundary.
#   Mounting the container runtime socket is the worst case: anything that can
#   write to it can start a privileged container and own the node.
# custom:
#   id: K8S-008
#   severity: critical
#   remediation: Remove the hostPath volume. If node-level data is genuinely needed, use a CSI driver or a dedicated DaemonSet with a documented exception.
#   frameworks:
#     cis-kubernetes: ["5.2.12"]
#     nist-800-53: ["AC-6", "SC-7"]
#     pci-dss-4: ["1.3.1", "2.2.4"]
package kubernetes.host_path

import data.lib.workload
import rego.v1

# Paths whose exposure is a node compromise rather than a smell.
sensitive := {
	"/": "the entire node filesystem",
	"/etc": "node configuration and credentials",
	"/proc": "every process on the node",
	"/sys": "kernel and device configuration",
	"/dev": "raw devices, including disks",
	"/boot": "the node's boot configuration",
	"/var/run/docker.sock": "the container runtime - one API call from a privileged container",
	"/run/containerd/containerd.sock": "the container runtime",
	"/var/lib/kubelet": "kubelet credentials for every pod on the node",
}

deny contains msg if {
	workload.is_workload
	some volume in object.get(workload.pod_spec, "volumes", [])
	path := volume.hostPath.path
	consequence := sensitive[path]
	msg := sprintf(
		"%s/%s: volume %q mounts %s, exposing %s",
		[input.kind, workload.name, volume.name, path, consequence],
	)
}

warn contains msg if {
	workload.is_workload
	some volume in object.get(workload.pod_spec, "volumes", [])
	path := volume.hostPath.path
	not sensitive[path]
	msg := sprintf(
		"%s/%s: volume %q mounts host path %q - confirm this is deliberate",
		[input.kind, workload.name, volume.name, path],
	)
}
