# METADATA
# title: Container root filesystems must be read-only
# description: |
#   A writable root filesystem lets an attacker who gets code execution drop
#   tooling and persist inside the container. Almost every workload can run
#   read-only with a tmpfs mounted where it genuinely needs to write.
# custom:
#   id: K8S-007
#   severity: medium
#   remediation: Set readOnlyRootFilesystem true, and add emptyDir volumes for the paths that need writing.
#   frameworks:
#     cis-kubernetes: ["5.2.11"]
#     nist-800-53: ["CM-5", "SI-7"]
#     pci-dss-4: ["2.2.4", "11.5.2"]
package kubernetes.read_only_root

import data.lib.workload
import rego.v1

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	object.get(workload.security_context(container), "readOnlyRootFilesystem", false) != true
	msg := sprintf(
		"%s/%s: container %q has a writable root filesystem",
		[input.kind, workload.name, container.name],
	)
}
