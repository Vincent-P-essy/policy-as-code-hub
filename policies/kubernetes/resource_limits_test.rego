package kubernetes.resource_limits_test

import data.kubernetes.resource_limits
import rego.v1

pod(resources) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c", "resources": resources}]},
}

test_no_limits_denied_for_both if {
	count(resource_limits.deny) == 2 with input as pod({})
}

test_memory_only_denies_cpu if {
	messages := resource_limits.deny with input as pod({"limits": {"memory": "512Mi"}})
	count(messages) == 1
	contains(concat(" ", messages), "cpu")
}

test_both_limits_allowed if {
	count(resource_limits.deny) == 0 with input as pod({
		"limits": {"memory": "512Mi", "cpu": "1"},
	})
}

test_requests_are_not_limits if {
	count(resource_limits.deny) == 2 with input as pod({
		"requests": {"memory": "256Mi", "cpu": "500m"},
	})
}
