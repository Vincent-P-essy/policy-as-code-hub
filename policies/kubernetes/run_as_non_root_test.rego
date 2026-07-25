package kubernetes.run_as_non_root_test

import data.kubernetes.run_as_non_root
import rego.v1

pod(container_context) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c", "securityContext": container_context}]},
}

test_no_context_denied if {
	count(run_as_non_root.deny) == 1 with input as pod({})
}

test_run_as_non_root_allowed if {
	count(run_as_non_root.deny) == 0 with input as pod({"runAsNonRoot": true})
}

test_explicit_uid_allowed if {
	count(run_as_non_root.deny) == 0 with input as pod({"runAsUser": 10001})
}

test_uid_zero_denied if {
	count(run_as_non_root.deny) == 2 with input as pod({"runAsUser": 0})
}

# The pod-level context is inherited unless the container overrides it.
test_pod_level_context_is_inherited if {
	count(run_as_non_root.deny) == 0 with input as {
		"kind": "Pod", "metadata": {"name": "p"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
			"containers": [{"name": "c"}],
		},
	}
}

# ...and the container's own setting wins when both are present. A checker that
# reads only the pod level calls this workload hardened.
test_container_overrides_the_pod if {
	count(run_as_non_root.deny) == 2 with input as {
		"kind": "Pod", "metadata": {"name": "p"},
		"spec": {
			"securityContext": {"runAsNonRoot": true, "runAsUser": 10001},
			"containers": [{"name": "c", "securityContext": {"runAsUser": 0, "runAsNonRoot": false}}],
		},
	}
}
