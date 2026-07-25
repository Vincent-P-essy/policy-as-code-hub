# METADATA
# title: Privilege escalation must be disallowed
# description: |
#   Without allowPrivilegeEscalation false, a setuid binary inside the container
#   can still raise privileges - which defeats the point of running as a
#   non-root user. It is the single cheapest control in this catalogue and the
#   most commonly missing.
# custom:
#   id: K8S-004
#   severity: high
#   remediation: Set securityContext.allowPrivilegeEscalation to false on every container.
#   frameworks:
#     cis-kubernetes: ["5.2.5"]
#     nist-800-53: ["AC-6(1)", "CM-7"]
#     pci-dss-4: ["2.2.4"]
package kubernetes.privilege_escalation

import data.lib.workload
import rego.v1

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	object.get(workload.security_context(container), "allowPrivilegeEscalation", true) != false
	msg := sprintf(
		"%s/%s: container %q allows privilege escalation - a setuid binary defeats the non-root user",
		[input.kind, workload.name, container.name],
	)
}
