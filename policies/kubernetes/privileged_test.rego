package kubernetes.privileged_test

import data.kubernetes.privileged
import rego.v1

deployment(security_context) := {
	"kind": "Deployment",
	"metadata": {"name": "payments-api"},
	"spec": {"template": {"spec": {"containers": [{
		"name": "api",
		"securityContext": security_context,
	}]}}},
}

test_privileged_is_denied if {
	count(privileged.deny) == 1 with input as deployment({"privileged": true})
}

test_not_privileged_is_allowed if {
	count(privileged.deny) == 0 with input as deployment({"privileged": false})
}

test_absent_security_context_is_allowed if {
	count(privileged.deny) == 0 with input as deployment({})
}

# The case a per-kind policy misses entirely.
test_init_container_is_checked if {
	count(privileged.deny) == 1 with input as {
		"kind": "Deployment",
		"metadata": {"name": "x"},
		"spec": {"template": {"spec": {
			"containers": [{"name": "app", "securityContext": {}}],
			"initContainers": [{"name": "setup", "securityContext": {"privileged": true}}],
		}}},
	}
}

test_cronjob_is_checked if {
	count(privileged.deny) == 1 with input as {
		"kind": "CronJob",
		"metadata": {"name": "nightly"},
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{
			"name": "job",
			"securityContext": {"privileged": true},
		}]}}}}},
	}
}

test_non_workload_is_ignored if {
	count(privileged.deny) == 0 with input as {"kind": "ConfigMap", "metadata": {"name": "c"}}
}
