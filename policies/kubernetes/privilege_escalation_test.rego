package kubernetes.privilege_escalation_test

import data.kubernetes.privilege_escalation
import rego.v1

pod(context) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c", "securityContext": context}]},
}

test_default_is_denied if {
	count(privilege_escalation.deny) == 1 with input as pod({})
}

test_explicit_false_allowed if {
	count(privilege_escalation.deny) == 0 with input as pod({"allowPrivilegeEscalation": false})
}

test_explicit_true_denied if {
	count(privilege_escalation.deny) == 1 with input as pod({"allowPrivilegeEscalation": true})
}
