#!/usr/bin/env python3
"""Build the Sysbox compatibility pair from a pinned local checkout."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from build import ROOT, elf_architecture, load_lock, sha256


COMPONENTS = {
    "root": ".",
    "fs": "sysbox-fs",
    "runc": "sysbox-runc",
    "ipc": "sysbox-ipc",
    "libs": "sysbox-libs",
    "fuse": "sysbox-fs/bazil",
}
PATCHES = (
    "patches/proc-transfer.patch",
    "patches/sysfs-transfer.patch",
    "patches/fuse-overlay-mount.patch",
    "patches/cilium-bpf-lab.patch",
)
OUTPUTS = ("sysbox-fs", "sysbox-runc")
BUILD = """set -eu
apt-get update -qq
apt-get install -y -qq --no-install-recommends gcc libc6-dev make protobuf-compiler libprotobuf-dev libseccomp-dev libapparmor-dev pkg-config
go install "$1"
make -C sysbox-ipc sysbox-ipc
cd sysbox-fs
CGO_ENABLED=1 go test -tags 'netgo osusergo' ./seccomp -run '^Test(PerfOutput|Cilium)' -count=1 -v
CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags 'netgo osusergo' -ldflags "-linkmode external -extldflags -static -X main.version=0.7.1-cilium-lab -X main.commitId=$2" -o /output/sysbox-fs ./cmd/sysbox-fs
cd ../sysbox-runc
CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags 'seccomp apparmor idmapped_mnt netgo osusergo' -ldflags "-linkmode external -extldflags -static -X main.version=0.7.1-cilium-lab -X main.commitId=$3" -o /output/sysbox-runc .
chown "$4:$5" /output/sysbox-fs /output/sysbox-runc
"""


def export_pinned_sources(lock, checkout, staging):
    for component, directory in COMPONENTS.items():
        upstream = (checkout / directory).resolve()
        rev = lock["components"][component]["revision"]
        actual = subprocess.check_output(
            ["git", "-C", upstream, "rev-parse", "HEAD"], text=True
        ).strip()
        if actual != rev:
            raise ValueError(f"{component}: expected pinned revision {rev}, got {actual}")
        target = staging / directory
        target.mkdir(parents=True, exist_ok=True)
        with subprocess.Popen(["git", "-C", upstream, "archive", rev], stdout=subprocess.PIPE) as process:
            with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                archive.extractall(target, filter="data")
            if process.wait() != 0:
                raise ValueError(f"{component}: archive failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path, help="Sysbox v0.7.1 checkout with initialized submodules")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-only", action="store_true")
    mode.add_argument("--output", type=Path, help="new directory for lab binaries and their manifest")
    args = parser.parse_args()
    lock = load_lock()

    with tempfile.TemporaryDirectory(prefix="sysbox-cilium-build-") as tmp:
        staging = Path(tmp)
        source = staging / "source"
        export_pinned_sources(lock, args.checkout, source)
        for patch in PATCHES:
            command = ["patch", "--batch", "--forward", "-p1", "-i", str(ROOT / patch)]
            subprocess.run([*command, "--dry-run"], cwd=source, check=True)
            subprocess.run(command, cwd=source, check=True)
        if args.check_only:
            return

        artifacts = staging / "artifacts"
        artifacts.mkdir()
        revisions = lock["components"]
        subprocess.run([
            "docker", "run", "--rm", "--mount", f"type=bind,src={source},dst=/src",
            "--mount", f"type=bind,src={artifacts},dst=/output", "-w", "/src",
            lock["builder"], "sh", "-c", BUILD, "build-cilium-lab",
            lock["generator"], revisions["fs"]["revision"], revisions["runc"]["revision"],
            str(os.getuid()), str(os.getgid()),
        ], check=True)
        architectures = {elf_architecture(artifacts / name) for name in OUTPUTS}
        if len(architectures) != 1:
            raise ValueError("lab binaries have different architectures")
        record = {
            "architecture": architectures.pop(),
            "builder": lock["builder"],
            "generator": lock["generator"],
            "sources": revisions,
            "input_sha256": {name: sha256(ROOT / name) for name in (
                *PATCHES, "scripts/build-cilium-lab.py", "scripts/build.py", "build/sources.lock.json",
            )},
            "output_sha256": {name: sha256(artifacts / name) for name in OUTPUTS},
        }
        (artifacts / "manifest.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        shutil.copytree(artifacts, args.output)


if __name__ == "__main__":
    main()
