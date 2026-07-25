# METADATA
# title: Containers must run as a non-root user
# description: |
#   A container process running as UID 0 is root inside the container, and a
#   container escape from root is a host compromise. runAsNonRoot alone is not
#   enough: it fails the pod at admission if the image happens to default to
#   root, but it does not say which user to use.
# custom:
#   id: K8S-003
#   severity: high
#   remediation: Set runAsNonRoot true and an explicit runAsUser above 0 on the pod or the container.
#   frameworks:
#     cis-kubernetes: ["5.2.6"]
#     nist-800-53: ["AC-6", "AC-6(1)"]
#     pci-dss-4: ["2.2.4", "7.2.1"]
package kubernetes.run_as_non_root

import data.lib.workload
import rego.v1

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	context := workload.security_context(container)
	not _runs_as_non_root(context)
	msg := sprintf(
		"%s/%s: container %q may run as root - set runAsNonRoot and runAsUser",
		[input.kind, workload.name, container.name],
	)
}

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	workload.security_context(container).runAsUser == 0
	msg := sprintf(
		"%s/%s: container %q sets runAsUser 0, which is root",
		[input.kind, workload.name, container.name],
	)
}

_runs_as_non_root(context) if context.runAsNonRoot == true

_runs_as_non_root(context) if {
	context.runAsUser > 0
}
