# METADATA
# title: All capabilities must be dropped, and dangerous ones never added
# description: |
#   Kubernetes grants 14 Linux capabilities by default, including SETUID, CHOWN
#   and NET_RAW. Almost no workload needs any of them. Separately, a handful of
#   capabilities are equivalent to root on the node and should never be added.
# custom:
#   id: K8S-005
#   severity: high
#   remediation: "Set capabilities.drop to [ALL], then add back only what breaks."
#   frameworks:
#     cis-kubernetes: ["5.2.7", "5.2.8", "5.2.9"]
#     nist-800-53: ["AC-6", "CM-7"]
#     pci-dss-4: ["2.2.4"]
package kubernetes.capabilities

import data.lib.workload
import rego.v1

# Each of these grants something equivalent to root on the node.
dangerous := {
	"SYS_ADMIN": "mount filesystems and manipulate namespaces - effectively root",
	"SYS_MODULE": "load kernel modules - a full node compromise",
	"SYS_PTRACE": "read and write the memory of other processes",
	"SYS_BOOT": "reboot the node",
	"DAC_READ_SEARCH": "bypass file read permission checks",
	"NET_ADMIN": "reconfigure the node network",
	"SYS_RAWIO": "direct I/O port and memory access",
}

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	not _drops_all(workload.security_context(container))
	msg := sprintf(
		"%s/%s: container %q keeps the default capability set - drop ALL first",
		[input.kind, workload.name, container.name],
	)
}

deny contains msg if {
	workload.is_workload
	some container in workload.containers
	some capability in object.get(workload.security_context(container), ["capabilities", "add"], [])
	name := upper(trim_prefix(upper(capability), "CAP_"))
	consequence := dangerous[name]
	msg := sprintf(
		"%s/%s: container %q adds %s, which grants: %s",
		[input.kind, workload.name, container.name, name, consequence],
	)
}

_drops_all(context) if {
	some dropped in object.get(context, ["capabilities", "drop"], [])
	upper(dropped) == "ALL"
}
