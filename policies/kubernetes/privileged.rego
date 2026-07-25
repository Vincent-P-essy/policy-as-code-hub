# METADATA
# title: Containers must not run privileged
# description: |
#   `privileged: true` disables every isolation mechanism at once - all
#   capabilities, all devices, no seccomp, no AppArmor. It is equivalent to
#   running the process on the host.
# custom:
#   id: K8S-001
#   severity: critical
#   remediation: Remove securityContext.privileged and add only the capabilities the workload actually needs.
#   frameworks:
#     cis-kubernetes: ["5.2.1"]
#     nist-800-53: ["AC-6", "AC-6(1)", "CM-7"]
#     pci-dss-4: ["2.2.4", "7.2.1"]
package kubernetes.privileged

import data.lib.workload
import rego.v1

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	workload.security_context(container).privileged == true
	msg := sprintf(
		"%s/%s: container %q runs privileged, which is equivalent to running on the host",
		[input.kind, workload.name, container.name],
	)
}
