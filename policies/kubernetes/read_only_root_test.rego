package kubernetes.read_only_root_test

import data.kubernetes.read_only_root
import rego.v1

pod(context) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c", "securityContext": context}]},
}

test_default_denied if {
	count(read_only_root.deny) == 1 with input as pod({})
}

test_read_only_allowed if {
	count(read_only_root.deny) == 0 with input as pod({"readOnlyRootFilesystem": true})
}
