package kubernetes.seccomp_test

import data.kubernetes.seccomp
import rego.v1

pod(context) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c", "securityContext": context}]},
}

test_missing_denied if {
	count(seccomp.deny) == 1 with input as pod({})
}

test_unconfined_denied_with_the_reason if {
	messages := seccomp.deny with input as pod({"seccompProfile": {"type": "Unconfined"}})
	count(messages) == 1
	contains(concat(" ", messages), "44 blocked syscalls")
}

test_runtime_default_allowed if {
	count(seccomp.deny) == 0 with input as pod({"seccompProfile": {"type": "RuntimeDefault"}})
}

test_pod_level_profile_is_inherited if {
	count(seccomp.deny) == 0 with input as {
		"kind": "Pod", "metadata": {"name": "p"},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			"containers": [{"name": "c"}],
		},
	}
}
