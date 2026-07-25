package kubernetes.capabilities_test

import data.kubernetes.capabilities
import rego.v1

pod(context) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c", "securityContext": context}]},
}

test_default_capabilities_denied if {
	count(capabilities.deny) == 1 with input as pod({})
}

test_drop_all_allowed if {
	count(capabilities.deny) == 0 with input as pod({"capabilities": {"drop": ["ALL"]}})
}

test_drop_all_lowercase_allowed if {
	count(capabilities.deny) == 0 with input as pod({"capabilities": {"drop": ["all"]}})
}

test_partial_drop_still_denied if {
	count(capabilities.deny) == 1 with input as pod({"capabilities": {"drop": ["NET_RAW"]}})
}

test_dangerous_add_denied_with_its_consequence if {
	messages := capabilities.deny with input as pod({
		"capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN"]},
	})
	count(messages) == 1
	contains(concat(" ", messages), "effectively root")
}

test_cap_prefix_is_normalised if {
	count(capabilities.deny) == 1 with input as pod({
		"capabilities": {"drop": ["ALL"], "add": ["CAP_SYS_PTRACE"]},
	})
}

test_harmless_add_allowed if {
	count(capabilities.deny) == 0 with input as pod({
		"capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
	})
}
