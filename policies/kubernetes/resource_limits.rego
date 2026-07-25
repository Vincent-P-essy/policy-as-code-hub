# METADATA
# title: Containers must declare CPU and memory limits
# description: |
#   A container with no memory limit can consume the node's memory and take its
#   neighbours down with it. That is a denial of service that needs no attacker,
#   and it is the most common cause of a node going NotReady.
# custom:
#   id: K8S-006
#   severity: medium
#   remediation: Set resources.limits.memory and resources.limits.cpu, and requests alongside them.
#   frameworks:
#     cis-kubernetes: ["5.7.3"]
#     nist-800-53: ["SC-5", "SC-6"]
#     pci-dss-4: ["2.2.1"]
package kubernetes.resource_limits

import data.lib.workload
import rego.v1

_required := {"memory", "cpu"}

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	some resource in _required
	not object.get(container, ["resources", "limits", resource], false)
	msg := sprintf(
		"%s/%s: container %q declares no %s limit",
		[input.kind, workload.name, container.name, resource],
	)
}
