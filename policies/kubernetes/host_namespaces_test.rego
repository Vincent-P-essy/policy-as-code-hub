package kubernetes.host_namespaces_test

import data.kubernetes.host_namespaces
import rego.v1

pod(spec) := {"kind": "Pod", "metadata": {"name": "p"}, "spec": object.union(
	{"containers": [{"name": "c"}]}, spec,
)}

test_host_pid_denied if {
	count(host_namespaces.deny) == 1 with input as pod({"hostPID": true})
}

test_host_network_denied if {
	count(host_namespaces.deny) == 1 with input as pod({"hostNetwork": true})
}

test_all_three_denied_separately if {
	count(host_namespaces.deny) == 3 with input as pod({
		"hostPID": true, "hostIPC": true, "hostNetwork": true,
	})
}

test_clean_pod_allowed if {
	count(host_namespaces.deny) == 0 with input as pod({})
}

test_explicit_false_allowed if {
	count(host_namespaces.deny) == 0 with input as pod({"hostPID": false})
}
