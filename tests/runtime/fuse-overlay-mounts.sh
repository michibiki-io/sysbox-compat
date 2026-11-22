#!/bin/sh
# Run as mapped root inside a disposable Sysbox container with /dev/fuse.
# Pass the absolute path to the compiled fuse-overlay-mount.c probe.
# Requires fuse-overlayfs, umount, mktemp and unshare.
set -eu

test -c /dev/fuse
parameter=/sys/module/fuse/parameters/allow_sys_admin_access
if test -r "$parameter"; then
    value=$(cat "$parameter")
    printf 'fuse.allow_sys_admin_access=%s\n' "$value"
    test "$value" = N
fi
probe=${1:?path to mount probe required}
test -x "$probe"
fixture=$(mktemp -d)
cleanup() {
    # All test mounts are scoped to a private mount namespace.
    umount "$fixture/merged" 2>/dev/null || true
    rm -rf "$fixture"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$fixture/lower/bind" "$fixture/lower/proc" "$fixture/lower/child-proc" \
    "$fixture/upper" "$fixture/work" "$fixture/merged" "$fixture/source" \
    "$fixture/lower/denied/target" "$fixture/ordinary" \
    "$fixture/lower/outer-sys" "$fixture/lower/child-sys"
chmod 755 "$fixture"
chmod 000 "$fixture/lower/denied"
printf 'fuse-overlay fixture\n' >"$fixture/lower/origin"
touch "$fixture/lower/not-directory"
printf 'bind fixture\n' >"$fixture/source/marker"

unshare --mount --propagation private sh -s "$fixture" "$probe" <<'MOUNTS'
set -eu
fixture=$1
probe=$2
fuse-overlayfs -o "lowerdir=$fixture/lower,upperdir=$fixture/upper,workdir=$fixture/work" "$fixture/merged"
test "$(cat "$fixture/merged/origin")" = 'fuse-overlay fixture'

# Run independent checks even if another check fails.
failed=0
if "$probe" private "$fixture/merged"; then
    printf 'PASS propagation\n'
else
    printf 'FAIL propagation\n' >&2
    failed=1
fi

if "$probe" bind "$fixture/source" "$fixture/merged/bind" &&
    test "$(cat "$fixture/merged/bind/marker")" = 'bind fixture'; then
    printf 'PASS bind\n'
else
    printf 'FAIL bind\n' >&2
    failed=1
fi

if "$probe" bind "$fixture/source" "$fixture/ordinary" &&
    test "$(cat "$fixture/ordinary/marker")" = 'bind fixture' &&
    "$probe" missing "$fixture/source" "$fixture/merged/missing" &&
    "$probe" denied "$fixture/source" "$fixture/merged/denied/target"; then
    printf 'PASS ordinary bind, absent and inaccessible targets\n'
else
    printf 'FAIL ordinary bind or target errno\n' >&2
    failed=1
fi

# The requester owns the new PID namespace but stays in the outer User
# namespace. Check the namespace-local PID view and the registered mask.
mask=$(stat -c '%d:%i' /proc/keys)
if unshare --mount --pid --fork sh -eu -c '
    test "$$" -eq 1
    "$1" proc "$2"
    test "$(readlink "$2/1/ns/pid")" = "$(readlink /proc/self/ns/pid)"
    test "$(stat -c "%d:%i" "$2/keys")" = "$3"
' sh "$probe" "$fixture/merged/proc" "$mask"; then
    printf 'PASS outer-user proc\n'
else
    printf 'FAIL outer-user proc\n' >&2
    failed=1
fi

# The child uses a procfd target and must receive locked copies of the
# registered proc protections. Capture the reference identities outside it.
readonly=$(stat -c '%d:%i' /proc/sysrq-trigger)
if unshare --user --map-root-user --mount --pid --fork sh -eu -c '
    test "$$" -eq 1
    "$1" proc-fd "$2"
    "$1" proc-bad-fd "${2%/*}/not-directory"
    test "$(readlink "$2/1/ns/pid")" = "$(readlink /proc/self/ns/pid)"
    test "$(stat -c "%d:%i" "$2/keys")" = "$3"
    test "$(stat -c "%d:%i" "$2/sysrq-trigger")" = "$4"
    awk -v path="$2/sysrq-trigger" "\$5 == path && \$6 ~ /(^|,)ro(,|\$)/ { seen = 1 } END { exit !seen }" /proc/self/mountinfo
    if umount -l "$2/sysrq-trigger"; then
        exit 1
    fi
    test "$(stat -c "%d:%i" "$2/sysrq-trigger")" = "$4"
' sh "$probe" "$fixture/merged/child-proc" "$mask" "$readonly"; then
    printf 'PASS direct-child-user procfd and mount protections\n'
else
    printf 'FAIL direct-child-user procfd or mount protections\n' >&2
    failed=1
fi

# Use an independently owned Network namespace for each fresh sysfs mount.
# Verify the registered mask's identity on both protected transfer paths.
sysmask=$(stat -c '%d:%i' /sys/firmware)
for scope in outer child; do
    set -- --mount --net
    if test "$scope" = child; then
        set -- --user --map-root-user "$@"
    fi
    if unshare "$@" sh -eu -c '
        "$1" sys-fd "$2"
        test "$(stat -c "%d:%i" "$2/firmware")" = "$3"
        test "$(stat -f -c "%t" "$2")" = 62656572
        if test "$4" = child && umount -l "$2/firmware"; then
            exit 1
        fi
    ' sh "$probe" "$fixture/merged/$scope-sys" "$sysmask" "$scope"; then
        printf 'PASS %s-user sysfs protected procfd mount\n' "$scope"
    else
        printf 'FAIL %s-user sysfs protected procfd mount\n' "$scope" >&2
        failed=1
    fi
done

# Detach children before allowing fuse-overlayfs to exit.
umount "$fixture/merged/bind" 2>/dev/null || true
umount "$fixture/merged"
exit "$failed"
MOUNTS
