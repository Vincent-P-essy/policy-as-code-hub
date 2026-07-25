package kubernetes.host_path_test

import data.kubernetes.host_path
import rego.v1

pod(volumes) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c"}], "volumes": volumes},
}

test_docker_socket_denied if {
	messages := host_path.deny with input as pod([
		{"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}},
	])
	count(messages) == 1
	contains(concat(" ", messages), "privileged container")
}

test_root_denied if {
	count(host_path.deny) == 1 with input as pod([
		{"name": "root", "hostPath": {"path": "/"}},
	])
}

test_ordinary_host_path_warns_rather_than_denies if {
	count(host_path.deny) == 0 with input as pod([
		{"name": "data", "hostPath": {"path": "/mnt/data"}},
	])
	count(host_path.warn) == 1 with input as pod([
		{"name": "data", "hostPath": {"path": "/mnt/data"}},
	])
}

test_non_host_volumes_ignored if {
	count(host_path.deny) == 0 with input as pod([{"name": "tmp", "emptyDir": {}}])
	count(host_path.warn) == 0 with input as pod([{"name": "tmp", "emptyDir": {}}])
}
