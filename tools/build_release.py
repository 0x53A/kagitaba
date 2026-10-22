#!/usr/bin/env python3
"""Build the Linux app and package an SPDX 2.3 inventory of Cargo's build units.

Run with `uv run --no-project tools/build_release.py`. No third-party Python
packages are needed. The precursor, not cargo metadata's workspace-wide resolve
graph, determines inclusion and features. Metadata only enriches those units.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"
REPOSITORY = "https://github.com/0x53A/kagitaba"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True).strip()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def make_sbom(precursor, metadata, lock, binary_hash, info):
    if precursor.get("version") != 1 or precursor.get("target") != info["target"]:
        raise ValueError("Unsupported Cargo precursor schema or target")
    units = precursor["crates"]
    root = precursor["root"]
    if type(root) is not int or not 0 <= root < len(units):
        raise ValueError("Invalid precursor root")
    packages = {p["id"]: p for p in metadata["packages"]}
    locked = {(p["name"], p["version"], p.get("source")): p for p in lock["package"]}
    # Traverse even though Cargo currently emits only reachable units. Never
    # invent a unit or silently omit an unknown package/dependency kind.
    reachable = set()
    pending = [root]
    while pending:
        index = pending.pop()
        if type(index) is not int or not 0 <= index < len(units):
            raise ValueError("Invalid precursor dependency index")
        if index in reachable:
            continue
        reachable.add(index)
        for dep in units[index]["dependencies"]:
            if dep["kind"] not in ("normal", "build"):
                raise ValueError("Unsupported precursor dependency kind")
            pending.append(dep["index"])
    app = packages[units[root]["id"]]
    if app["name"] != "kagitaba-app" or "bin" not in units[root]["kind"]:
        raise ValueError("Precursor is not for the Kagitaba application")
    if "smoke" in units[root]["features"]:
        raise ValueError("Refusing to package the screenshot-enabled smoke build")
    spdx_packages = [{
        "SPDXID": "SPDXRef-Application", "name": "kagitaba-app",
        "versionInfo": app["version"], "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
        "licenseDeclared": app.get("license") or "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "checksums": [{"algorithm": "SHA256", "checksumValue": binary_hash}],
        "sourceInfo": json.dumps(info, sort_keys=True),
        "primaryPackagePurpose": "APPLICATION",
    }]
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": "SPDXRef-Application"},
        {"spdxElementId": "SPDXRef-Application", "relationshipType": "GENERATED_FROM",
         "relatedSpdxElement": f"SPDXRef-Crate-{root}"},
    ]
    licenses = []
    for index in sorted(reachable):
        unit = units[index]
        package = packages[unit["id"]]
        name, version, source = package["name"], package["version"], package.get("source")
        record = locked[(name, version, source)]
        declared = package.get("license")
        # Cargo also accepts the legacy slash spelling for dual licensing.
        license_expression = declared.replace("/", " OR ") if declared else "NOASSERTION"
        package_id = f"SPDXRef-Crate-{index}"
        crates_io = source == "registry+https://github.com/rust-lang/crates.io-index"
        entry = {
            "SPDXID": package_id, "name": name, "versionInfo": version,
            "downloadLocation": f"https://crates.io/api/v1/crates/{name}/{version}/download" if crates_io else "NOASSERTION",
            "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_expression, "copyrightText": "NOASSERTION",
            "sourceInfo": json.dumps({"cargo_id": unit["id"], "kind": unit["kind"],
                                      "features": unit["features"]}, sort_keys=True),
        }
        if source is None:
            entry["sourceInfo"] += f"; workspace source commit {info['commit']}; dirty={info['dirty']}"
        if crates_io:
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": record["checksum"]}]
            entry["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER",
                                      "referenceType": "purl", "referenceLocator": f"pkg:cargo/{name}@{version}"}]
        spdx_packages.append(entry)
        licenses.append({"unit": index, "name": name, "version": version,
                         "license": declared, "license_file": package.get("license_file"),
                         "needs_review": not bool(declared)})
        for dep in unit["dependencies"]:
            dependency_id = f"SPDXRef-Crate-{dep['index']}"
            # SPDX BUILD_DEPENDENCY_OF points from the build tool to its user.
            relationships.append({
                "spdxElementId": dependency_id if dep["kind"] == "build" else package_id,
                "relationshipType": "BUILD_DEPENDENCY_OF" if dep["kind"] == "build" else "DEPENDS_ON",
                "relatedSpdxElement": package_id if dep["kind"] == "build" else dependency_id,
            })
    document = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"kagitaba-app-{info['target']}",
        "documentNamespace": f"{REPOSITORY}/sbom/{uuid.uuid4()}",
        "creationInfo": {"creators": ["Tool: kagitaba-build-sbom-1"], "created": info["created"]},
        "comment": "Cargo build-unit inventory including build scripts and proc-macros. "
                   "Excludes Rust sysroot internals, OS libraries/drivers loaded at runtime, "
                   "and non-Cargo inputs introduced by build scripts. Registry checksums identify "
                   "source archives; only SPDXRef-Application hashes the executable. "
                   "License declarations are not a license-compliance audit.",
        "packages": spdx_packages, "relationships": relationships,
    }
    return document, licenses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/dist")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("Output directory must be absent or empty; choose a new --output")
    info = {
        "commit": command("git", "rev-parse", "HEAD"),
        "dirty": bool(command("git", "status", "--porcelain", "--untracked-files=normal")),
        "target": TARGET, "profile": "release", "features": "default (no smoke)",
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        "rustc": command("rustc", "-Vv"), "cargo": command("cargo", "-V"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    }
    if os.environ.get("GITHUB_ACTIONS") == "true" and info["dirty"]:
        raise ValueError("GitHub release builds require a clean checkout")
    # Cargo can reuse a binary compiled without SBOM capture without emitting
    # its missing precursor. Keep this cache separate from ordinary builds.
    build_dir = ROOT / "target/sbom-build"
    env = dict(os.environ, RUSTC_BOOTSTRAP="1", CARGO_BUILD_SBOM="true",
               CARGO_TARGET_DIR=str(build_dir))
    subprocess.run(["cargo", "-Z", "sbom", "build", "--locked", "--release",
                    "--target", TARGET, "-p", "kagitaba-app", "--bin", "kagitaba-app"],
                   cwd=ROOT, env=env, check=True)
    binary = build_dir / TARGET / "release/kagitaba-app"
    precursor_path = binary.with_name(binary.name + ".cargo-sbom.json")
    precursor = json.loads(precursor_path.read_text())
    if precursor["rustc"]["verbose_version"].strip() != info["rustc"]:
        raise ValueError("Precursor compiler differs from the packaging compiler")
    metadata = json.loads(command("cargo", "metadata", "--locked", "--offline",
                                  "--filter-platform", TARGET, "--format-version", "1"))
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    sbom, licenses = make_sbom(precursor, metadata, lock, sha256(binary), info)
    if sha256(ROOT / "Cargo.lock") != info["cargo_lock_sha256"]:
        raise ValueError("Cargo.lock changed during the build")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, output / "kagitaba-app")
    shutil.copy2(ROOT / "assets/fonts/LICENSE", output / "FONT-LICENSE.txt")
    shutil.copy2(precursor_path, output / "cargo-sbom.json")
    write_json(output / "sbom.spdx.json", sbom)
    write_json(output / "licenses.json", licenses)
    write_json(output / "build-info.json", info)
    files = sorted(output.iterdir())
    (output / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files))
    archive = output / f"kagitaba-app-{TARGET}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for path in [*files, output / "SHA256SUMS"]:
            tar.add(path, arcname=path.name)
    print(f"Built {archive}")
    print(f"SBOM: {len(sbom['packages']) - 1} Cargo build units; "
          f"{sum(p['needs_review'] for p in licenses)} license declarations need review")


if __name__ == "__main__":
    main()
