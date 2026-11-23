#!/usr/bin/env python3
"""Verify perf and JIT delegation in an isolated Sysbox daemon on cgroup v2."""

import argparse
from contextlib import ExitStack, contextmanager
import errno
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import tempfile
import uuid


REGISTRATION = Path("/run/sysbox/perf-output-lab")


def docker(*args):
    return subprocess.check_output(["docker", *map(str, args)], text=True).strip()


@contextmanager
def test_container(runtime, image, probe, lab):
    name = f"sysbox-probe-{uuid.uuid4().hex}"
    with tempfile.TemporaryDirectory(prefix="jit-", dir=lab) as directory:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            endpoint = Path(directory) / "probe.sock"
            listener.bind(str(endpoint))
            endpoint.chmod(0o666)
            listener.listen(1)
            listener.settimeout(10)
            docker("run", "--detach", "--pull", "never", "--runtime", runtime, "--name",
                   name, "--cap-add", "SYS_ADMIN", "--mount", f"type=bind,src={probe},dst=/perf-probe,readonly",
                   "--mount", f"type=bind,src={endpoint},dst=/jit-probe.sock,readonly",
                   "--entrypoint", "sleep", image, "600")
            try:
                raw_id, raw_pid = docker("inspect", "-f", "{{.Id}} {{.State.Pid}}", name).split()
                scope = next(line[3:] for line in Path(f"/proc/{int(raw_pid)}/cgroup").read_text().splitlines()
                             if line.startswith("0::"))
                with subprocess.Popen(["docker", "exec", "-i", name, "/perf-probe"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            fd = connection.fileno()
                            subprocess.run([str(probe), "--send-jit-fd", str(fd)],
                                           pass_fds=(fd,), timeout=10, check=True)
                        yield raw_id, scope, process
                    finally:
                        process.stdin.close()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            # Removing the owned container also stops the in-container probe.
                            process.kill()
            finally:
                docker("rm", "--force", name)


def probe_result(process, command="probe"):
    process.stdin.write(command + "\n")
    process.stdin.flush()
    ready, _, _ = select.select([process.stdout], [], [], 10)
    if not ready:
        raise TimeoutError("live probe did not reply")
    reply = process.stdout.readline().strip()
    if not re.fullmatch(r"-?\d+", reply) or int(reply) < 0:
        raise RuntimeError(f"{command} failed to validate its file descriptor")
    return int(reply)


def require(condition, label):
    if not condition:
        raise RuntimeError(label)
    print(f"PASS {label}", flush=True)


class JobFailure(Exception):
    pass


@contextmanager
def register(outer_id, scope):
    with tempfile.NamedTemporaryFile(mode="w", dir=REGISTRATION.parent, delete=False) as record:
        staging = Path(record.name)
        try:
            record.write(f"{outer_id} {scope}\n")
            record.flush()
            os.fchmod(record.fileno(), 0o400)
            os.link(staging, REGISTRATION)
        finally:
            staging.unlink()
    try:
        yield
    finally:
        REGISTRATION.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lab", type=Path, help="disposable daemon root with docker.sock and run-sysbox")
    parser.add_argument("image", help="local image ID for an image with sleep")
    parser.add_argument("probe", type=Path, help="compiled static cilium-lab-perf.c")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--baseline-only", action="store_true")
    mode.add_argument("--native-results", type=int, nargs=2, metavar=("PERF", "JIT"),
                      help="baseline perf errno or zero, and baseline JIT length")
    args = parser.parse_args()
    lab = args.lab.resolve(strict=True)
    if (os.geteuid() != 0 or os.environ.get("DOCKER_HOST") != f"unix://{lab}/docker.sock"
            or not Path("/run/sysbox").samefile(lab / "run-sysbox")
            or REGISTRATION.exists() or REGISTRATION.is_symlink()):
        parser.error("requires the disposable daemon, its private Sysbox mount, and no previous registration")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", args.image):
        parser.error("use a pinned local image ID")

    probe = args.probe.resolve(strict=True)
    if args.baseline_only:
        with test_container("sysbox-baseline", args.image, probe, lab) as (_, _, baseline):
            print(probe_result(baseline), probe_result(baseline, "jit"), flush=True)
        return
    native_perf, native_jit = args.native_results
    with ExitStack() as stack:
        disabled = stack.enter_context(test_container("sysbox-lab-off", args.image, probe, lab))[2]
        outer, scope, active = stack.enter_context(test_container("sysbox-lab", args.image, probe, lab))
        other_outer, other_scope, other = stack.enter_context(test_container("sysbox-lab", args.image, probe, lab))
        require(probe_result(disabled) == native_perf, "routing disabled matches the unpatched runtime")
        require(probe_result(disabled, "jit") == native_jit, "routing disabled preserves native JIT visibility")
        require(probe_result(active) == errno.EPERM, "unregistered request denied")
        require(probe_result(active, "jit") == native_jit, "unregistered request preserves native JIT visibility")
        require(scope != other_scope, "jobs occupy different cgroups")
        with register(other_outer, scope):
            require(probe_result(other) == errno.EPERM, "registered ID in a different cgroup denied")
            require(probe_result(other, "jit") == native_jit, "JIT preserves native visibility in a mismatched cgroup")
        for failing in (False, True):
            try:
                with register(outer, scope):
                    require(probe_result(active) == 0, "registered request opened a usable perf ring")
                    require(probe_result(active, "jit") > native_jit, "registered JIT response exposes a length")
                    require(probe_result(other) == errno.EPERM, "other job denied")
                    require(probe_result(other, "jit") == native_jit, "other job keeps native JIT visibility")
                    require(probe_result(active, "out-of-policy") == errno.EPERM, "unsupported perf attributes denied")
                    if failing:
                        raise JobFailure()
            except JobFailure:
                pass
            label = "failed job" if failing else "successful job"
            require(not REGISTRATION.exists(), f"{label} registration removed")
            require(probe_result(active) == errno.EPERM, f"{label} live requester denied after removal")
            require(probe_result(active, "jit") == native_jit, f"{label} live requester returned to native JIT visibility")


if __name__ == "__main__":
    main()
