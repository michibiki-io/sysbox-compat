"""Verify the SPDX attestation exported by the FUSE Docker fixture."""
import hashlib
import json
import sys
import tarfile


def load_blob(archive, digest):
    algorithm, value = digest.split(":", 1)
    with archive.extractfile(f"blobs/{algorithm}/{value}") as data:
        payload = data.read()
    if hashlib.new(algorithm, payload).hexdigest() != value:
        raise ValueError(f"content digest mismatch: {digest}")
    return json.loads(payload)


def manifests(archive, index):
    for descriptor in index["manifests"]:
        if descriptor.get("mediaType") == "application/vnd.oci.image.index.v1+json":
            yield from manifests(archive, load_blob(archive, descriptor["digest"]))
        else:
            yield descriptor


def verify(archive):
    with archive.extractfile("index.json") as data:
        entries = list(manifests(archive, json.load(data)))
    images = [
        entry for entry in entries
        if entry.get("platform", {}).get("architecture") not in (None, "unknown")
    ]
    if len(images) != 1:
        raise ValueError("expected one platform image")
    subject = images[0]["digest"]
    if len(load_blob(archive, subject)["layers"]) < 3:
        raise ValueError("expected a multilayer image")

    attestations = [
        entry for entry in entries
        if entry.get("annotations", {}).get("vnd.docker.reference.digest") == subject
    ]
    if len(attestations) != 1:
        raise ValueError("expected one attestation manifest linked to the image")
    layers = load_blob(archive, attestations[0]["digest"])["layers"]
    for layer in layers:
        statement = load_blob(archive, layer["digest"])
        if statement.get("predicateType") != "https://spdx.dev/Document":
            continue
        if any(item["digest"].get("sha256") == subject.removeprefix("sha256:")
               for item in statement["subject"]):
            print(f"PASS digest-linked SPDX {subject}")
            return
    raise ValueError("SPDX statement does not name the image digest")


if __name__ == "__main__":
    with tarfile.open(sys.argv[1], "r:*") as source:
        verify(source)
