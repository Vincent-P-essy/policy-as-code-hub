package kubernetes.image_tag_test

import data.kubernetes.image_tag
import rego.v1

pod(image) := {
	"kind": "Pod", "metadata": {"name": "p"},
	"spec": {"containers": [{"name": "c", "image": image}]},
}

test_latest_denied if {
	count(image_tag.deny) == 1 with input as pod("nginx:latest")
}

test_untagged_denied if {
	count(image_tag.deny) == 1 with input as pod("nginx")
}

test_version_tag_warns_only if {
	count(image_tag.deny) == 0 with input as pod("nginx:1.27.3")
	count(image_tag.warn) == 1 with input as pod("nginx:1.27.3")
}

test_digest_is_clean if {
	image := concat("", ["nginx@sha256:", concat("", ["a" | some _ in numbers.range(1, 64)])])
	count(image_tag.deny) == 0 with input as pod(image)
	count(image_tag.warn) == 0 with input as pod(image)
}
