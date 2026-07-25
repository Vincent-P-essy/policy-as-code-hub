# METADATA
# title: A seccomp profile must be set
# description: |
#   The default seccomp profile blocks around 44 syscalls that no ordinary
#   workload needs and that appear in most container-escape chains. Unconfined
#   restores every one of them.
# custom:
#   id: K8S-010
#   severity: high
#   remediation: "Set seccompProfile.type to RuntimeDefault, or supply a narrower Localhost profile."
#   frameworks:
#     cis-kubernetes: ["5.7.2"]
#     nist-800-53: ["CM-7", "SI-3"]
#     pci-dss-4: ["2.2.4"]
package kubernetes.seccomp

import data.lib.workload
import rego.v1

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	profile := object.get(workload.security_context(container), ["seccompProfile", "type"], "")
	profile == "Unconfined"
	msg := sprintf(
		"%s/%s: container %q sets seccomp Unconfined, restoring ~44 blocked syscalls",
		[input.kind, workload.name, container.name],
	)
}

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	object.get(workload.security_context(container), ["seccompProfile", "type"], "") == ""
	msg := sprintf(
		"%s/%s: container %q sets no seccomp profile",
		[input.kind, workload.name, container.name],
	)
}
