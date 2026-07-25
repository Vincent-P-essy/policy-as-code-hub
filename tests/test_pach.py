"""Catalogue integrity, and the policies actually doing what they claim."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from pach.catalogue import build, validate
from pach.evaluate import build_bundle, check, evaluate, run_tests

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"
EXAMPLES = ROOT / "examples"

pytestmark = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="the opa binary is required: this project curates policies, it does not reimplement Rego",
)


@pytest.fixture(scope="module")
def catalogue():
    return build(POLICIES)


class TestCatalogue:
    def test_reads_every_policy(self, catalogue):
        assert len(catalogue) >= 10

    def test_helper_packages_are_not_counted_as_policies(self, catalogue):
        # A package with no custom.id enforces nothing; listing it would
        # inflate the catalogue.
        assert "lib.workload" in catalogue.helpers
        assert not any(p.package == "lib.workload" for p in catalogue.policies)

    def test_policy_ids_are_unique(self, catalogue):
        assert catalogue.duplicate_ids() == []

    def test_the_frameworks_claimed_in_the_readme_are_present(self, catalogue):
        assert set(catalogue.frameworks()) == {"cis-kubernetes", "nist-800-53", "pci-dss-4"}

    def test_every_policy_maps_to_at_least_one_control(self, catalogue):
        for policy in catalogue.policies:
            assert policy.frameworks, policy.id

    def test_every_policy_has_a_remediation(self, catalogue):
        # A policy that says what is wrong and not what to do is a complaint.
        for policy in catalogue.policies:
            assert policy.remediation.strip(), policy.id

    def test_validation_is_clean(self, catalogue):
        assert validate(catalogue, POLICIES) == []

    def test_validation_catches_a_missing_mapping(self, catalogue, tmp_path):
        from dataclasses import replace

        from pach.catalogue import Catalogue

        broken = Catalogue(policies=[replace(catalogue.policies[0], frameworks={})])
        problems = validate(broken, POLICIES)
        assert any("maps to no framework" in p for p in problems)

    def test_serialises(self, catalogue):
        json.dumps(catalogue.to_dict())


class TestRegoQuality:
    def test_opa_check_strict_passes(self):
        ok, output = check(POLICIES, strict=True)
        assert ok, output

    def test_every_rego_test_passes(self):
        result = run_tests(POLICIES)
        assert result.ok, result.failures
        assert result.passed >= 40

    def test_every_policy_has_tests_beside_it(self, catalogue):
        for policy in catalogue.policies:
            source = ROOT / policy.file
            assert source.with_name(source.stem + "_test.rego").exists(), policy.id


class TestEvaluation:
    def test_the_bad_manifest_is_denied(self, catalogue):
        result = evaluate([EXAMPLES / "bad-deployment.yaml"], catalogue, policy_dir=POLICIES)
        assert not result.clean
        assert len(result.denials) >= 10

    def test_the_hardened_manifest_is_clean(self, catalogue):
        result = evaluate([EXAMPLES / "good-deployment.yaml"], catalogue, policy_dir=POLICIES)
        assert result.clean, [v.message for v in result.denials]

    def test_violations_carry_the_policy_and_its_remediation(self, catalogue):
        result = evaluate([EXAMPLES / "bad-deployment.yaml"], catalogue, policy_dir=POLICIES)
        with_policy = [v for v in result.violations if v.policy]
        assert with_policy
        assert all(v.policy.remediation for v in with_policy)

    def test_critical_findings_sort_first(self, catalogue):
        result = evaluate([EXAMPLES / "bad-deployment.yaml"], catalogue, policy_dir=POLICIES)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranks = [order[v.severity] for v in result.denials]
        assert ranks == sorted(ranks)

    def test_warnings_do_not_fail_the_evaluation(self, catalogue):
        # A tag-pinned image warns; only a floating tag denies.
        import yaml as _yaml

        document = _yaml.safe_load((EXAMPLES / "good-deployment.yaml").read_text())
        containers = document["spec"]["template"]["spec"]["containers"]
        containers[0]["image"] = "registry.internal/payments-api:2.4.1"

        path = Path("/tmp/pach-warn.yaml")
        path.write_text(_yaml.safe_dump(document))
        result = evaluate([path], catalogue, policy_dir=POLICIES)
        assert result.clean
        assert result.warnings

    def test_missing_manifest_is_named(self, catalogue):
        from pach.catalogue import CatalogueError

        with pytest.raises(CatalogueError, match="not found"):
            evaluate(["/nope/missing.yaml"], catalogue, policy_dir=POLICIES)

    def test_serialises(self, catalogue):
        result = evaluate([EXAMPLES / "bad-deployment.yaml"], catalogue, policy_dir=POLICIES)
        json.dumps(result.to_dict())


class TestBundle:
    def test_builds(self, tmp_path):
        path = build_bundle(POLICIES, tmp_path / "policies.tar.gz", revision="test-1")
        assert path.exists()
        assert path.stat().st_size > 500

    def test_bundle_is_a_real_tarball_containing_the_policies(self, tmp_path):
        import tarfile

        path = build_bundle(POLICIES, tmp_path / "b.tar.gz")
        with tarfile.open(path) as archive:
            names = archive.getnames()
        assert any(n.endswith(".rego") for n in names)
        assert any("manifest" in n for n in names)
