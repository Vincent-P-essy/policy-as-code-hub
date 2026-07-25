# METADATA
# title: Images must be pinned to a digest, not a floating tag
# description: |
#   A tag can be moved. `:latest` moves constantly, and even a version tag can
#   be republished, so what a cluster runs after a restart is not necessarily
#   what was reviewed. A digest cannot be moved.
# custom:
#   id: K8S-009
#   severity: medium
#   remediation: "Pin the digest: image: registry/name@sha256:<digest>."
#   frameworks:
#     cis-kubernetes: ["5.5.1"]
#     nist-800-53: ["CM-2", "SI-7"]
#     pci-dss-4: ["6.3.2", "11.5.2"]
package kubernetes.image_tag

import data.lib.workload
import rego.v1

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	endswith(container.image, ":latest")
	msg := sprintf(
		"%s/%s: container %q uses :latest, which moves under you",
		[input.kind, workload.name, container.name],
	)
}

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	not contains(container.image, ":")
	not contains(container.image, "@")
	msg := sprintf(
		"%s/%s: container %q has no tag, so it resolves to :latest",
		[input.kind, workload.name, container.name],
	)
}

warn contains msg if {
	workload.is_workload
	some container in workload.containers
	not contains(container.image, "@sha256:")
	contains(container.image, ":")
	not endswith(container.image, ":latest")
	msg := sprintf(
		"%s/%s: container %q is pinned by tag, not by digest - a tag can be republished",
		[input.kind, workload.name, container.name],
	)
}
