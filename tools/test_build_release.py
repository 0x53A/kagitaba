"""Regression checks for the security-relevant SBOM mapping boundaries."""
import copy
import unittest

from build_release import TARGET, make_sbom


class BuildSbomTests(unittest.TestCase):
    def setUp(self):
        self.info = {"target": TARGET, "commit": "a" * 40, "dirty": False,
                     "created": "2026-10-10T00:00:00Z"}
        self.precursor = {
            "version": 1, "target": TARGET, "root": 0,
            "crates": [
                {"id": "app", "kind": ["bin"], "features": [],
                 "dependencies": [{"index": 1, "kind": "normal"}, {"index": 2, "kind": "build"}]},
                {"id": "dep", "kind": ["lib"], "features": ["runtime"], "dependencies": []},
                {"id": "dep", "kind": ["lib"], "features": ["generator"], "dependencies": []},
                {"id": "unused", "kind": ["lib"], "features": [], "dependencies": []},
            ],
        }
        source = "registry+https://github.com/rust-lang/crates.io-index"
        self.metadata = {"packages": [
            {"id": "app", "name": "kagitaba-app", "version": "0.1.0", "source": None, "license": None},
            {"id": "dep", "name": "dependency", "version": "1.0.0", "source": source, "license": "MIT OR Apache-2.0"},
            {"id": "unused", "name": "unused", "version": "1.0.0", "source": source, "license": "MIT"},
        ]}
        self.lock = {"package": [
            {"name": "kagitaba-app", "version": "0.1.0"},
            {"name": "dependency", "version": "1.0.0", "source": source, "checksum": "b" * 64},
        ]}

    def build(self):
        return make_sbom(self.precursor, self.metadata, self.lock, "c" * 64, self.info)

    def test_actual_units_and_features_not_workspace_resolve_graph(self):
        sbom, licenses = self.build()
        self.assertEqual(len(sbom["packages"]), 4)
        self.assertNotIn("unused", [p["name"] for p in sbom["packages"]])
        self.assertIn('"runtime"', sbom["packages"][2]["sourceInfo"])
        self.assertIn('"generator"', sbom["packages"][3]["sourceInfo"])
        self.assertEqual(sbom["packages"][0]["checksums"][0]["checksumValue"], "c" * 64)
        self.assertEqual(sbom["packages"][2]["checksums"][0]["checksumValue"], "b" * 64)
        self.assertTrue(licenses[0]["needs_review"])
        self.assertFalse(licenses[1]["needs_review"])

    def test_build_edges_have_spdx_direction(self):
        sbom, _ = self.build()
        self.assertIn({"spdxElementId": "SPDXRef-Crate-2", "relationshipType": "BUILD_DEPENDENCY_OF",
                       "relatedSpdxElement": "SPDXRef-Crate-0"}, sbom["relationships"])
        self.assertIn({"spdxElementId": "SPDXRef-Crate-0", "relationshipType": "DEPENDS_ON",
                       "relatedSpdxElement": "SPDXRef-Crate-1"}, sbom["relationships"])

    def test_schema_target_smoke_and_bad_edges_fail_closed(self):
        original = copy.deepcopy(self.precursor)
        mutations = [
            lambda p: p.update(version=2),
            lambda p: p.update(target="aarch64-unknown-linux-gnu"),
            lambda p: p.update(root=-1),
            lambda p: p["crates"][0].update(features=["smoke"]),
            lambda p: p["crates"][0]["dependencies"][0].update(index=-1),
            lambda p: p["crates"][0]["dependencies"][0].update(index=True),
            lambda p: p["crates"][0]["dependencies"][0].update(kind="unexpected"),
        ]
        for mutate in mutations:
            self.precursor = copy.deepcopy(original)
            mutate(self.precursor)
            with self.assertRaises(ValueError):
                self.build()

    def test_missing_metadata_or_lock_record_is_not_silently_omitted(self):
        original = copy.deepcopy(self.metadata)
        self.metadata["packages"] = self.metadata["packages"][:1]
        with self.assertRaises(KeyError):
            self.build()
        self.metadata = original
        self.lock["package"] = self.lock["package"][:1]
        with self.assertRaises(KeyError):
            self.build()


if __name__ == "__main__":
    unittest.main()
