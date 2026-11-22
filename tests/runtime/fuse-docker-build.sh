#!/bin/sh
# Run inside a disposable Sysbox container with rootful Docker and Buildx.
# Accepts the expected Docker driver. The overlay2 case tests BuildKit SBOM.
set -eu

driver=${1:?expected Docker driver required}
case "$driver" in
    fuse-overlayfs) ;;
    overlay2) : "${FUSE_TEST_BUILDKIT:?patched BuildKit fixture image required for the SBOM test}" ;;
    *) printf 'Expected fuse-overlayfs or overlay2\n' >&2; exit 2 ;;
esac
test "$(docker info --format '{{.Driver}}')" = "$driver"
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
fixture=$(mktemp -d)
label="sysbox-fuse-test-$$"
image="$label:result"
buildkit="$label:buildkit"
cleanup() {
    docker buildx rm "$label" >/dev/null 2>&1 || true
    docker image rm "$image" "$buildkit" >/dev/null 2>&1 || true
    rm -rf "$fixture"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

base=${FUSE_TEST_BASE:-alpine:3.21}
docker pull "$base"
docker image inspect "$base" --format 'base={{json .RepoDigests}}'
mkdir "$fixture/app"
printf 'FROM %s\n' "$base" >"$fixture/app/Dockerfile"
cat >>"$fixture/app/Dockerfile" <<'DOCKERFILE'
RUN printf 'proof\n' >/proof
RUN test "$(cat /proof)" = proof && echo second >/second
DOCKERFILE

if test "$driver" = fuse-overlayfs; then
    DOCKER_BUILDKIT=1 docker build --progress=plain -t "$image" "$fixture/app"
    test "$(docker run --rm "$image" cat /proof)" = proof
    docker buildx create --name "$label" --driver docker-container
    docker buildx inspect --bootstrap "$label"
    printf 'PASS Docker build, image run, and Buildx bootstrap\n'
else
    revision=$(docker image inspect "$FUSE_TEST_BUILDKIT" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
    test "$revision" = 412cc86ad3c4252b82e929f9b1b1ad167376ded8
    printf 'BuildKit fixture source=%s\n' "$revision"
    mkdir "$fixture/worker"
    printf 'FROM %s\nRUN apk add --no-cache fuse-overlayfs\n' \
        "$FUSE_TEST_BUILDKIT" >"$fixture/worker/Dockerfile"
    DOCKER_BUILDKIT=1 docker build --progress=plain -t "$buildkit" "$fixture/worker"
    # Preload the fixture image before Buildx starts the docker-container worker.
    printf '[worker.oci]\n  snapshotter = "fuse-overlayfs"\n' >"$fixture/buildkitd.toml"
    docker buildx create --name "$label" --driver docker-container \
        --driver-opt "image=$buildkit" --buildkitd-config "$fixture/buildkitd.toml"
    docker buildx inspect --bootstrap "$label" >"$fixture/worker-info"
    cat "$fixture/worker-info"
    grep -Eq 'worker.snapshotter:[[:space:]]*fuse-overlayfs' "$fixture/worker-info"
    docker buildx build --builder "$label" --tag "$image" --progress=plain --sbom=true --provenance=false \
        --output="type=oci,dest=$fixture/image.tar" "$fixture/app"
    python3 "$script_dir/fuse-verify-spdx.py" "$fixture/image.tar"
fi
