#!/usr/bin/env python3
"""Verify perf and JIT delegation in an isolated Sysbox daemon on cgroup v2."""

import argparse
from contextlib import ExitStack, contextmanager
import errno
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import tempfile
import uuid


REGISTRATION = Path("/run/sysbox/perf-output-lab")
COMMANDS = ("probe", "out-of-policy", "ordinary-perf", "jit", "jit-unsupported")


def docker(*args):
    return subprocess.check_output(["docker", *map(str, args)], text=True).strip()


@contextmanager
def test_container(runtime, image, probe, lab, seccomp=None):
    name = f"sysbox-probe-{uuid.uuid4().hex}"
    with tempfile.TemporaryDirectory(prefix="jit-", dir=lab) as directory:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            endpoint = Path(directory) / "probe.sock"
            listener.bind(str(endpoint))
            endpoint.chmod(0o666)
            listener.listen(1)
            listener.settimeout(10)
            security = ("--security-opt", f"seccomp={seccomp}") if seccomp else ()
            docker("run", "--detach", "--pull", "never", "--runtime", runtime, "--name",
                   name, "--cap-add", "SYS_ADMIN", "--mount", f"type=bind,src={probe},dst=/perf-probe,readonly",
                   "--mount", f"type=bind,src={endpoint},dst=/jit-probe.sock,readonly",
                   *security, "--entrypoint", "sleep", image, "600")
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


def probe_result(process, command):
    process.stdin.write(command + "\n")
    process.stdin.flush()
    ready, _, _ = select.select([process.stdout], [], [], 10)
    if not ready:
        raise TimeoutError("live probe did not reply")
    reply = process.stdout.readline().strip()
    if not re.fullmatch(r"\d+( \d+)*", reply):
        raise RuntimeError(f"{command} failed to validate its file descriptor")
    fields = list(map(int, reply.split()))
    if len(fields) == 1 and (not command.startswith("jit") or fields[0] != 0):
        return fields
    if command.startswith("jit") and len(fields) == 13 and fields[0] == 0:
        return fields
    raise RuntimeError(f"{command} returned unexpected fields: {reply}")


def snapshot(process):
    return {command: probe_result(process, command) for command in COMMANDS}


def compare_native(process, native, label, commands=COMMANDS):
    for command in commands:
        observed = probe_result(process, command)
        require(observed == native[command],
                f"{label}: {command} matches native ({observed} vs {native[command]})")


def require(condition, label):
    if not condition:
        raise RuntimeError(label)
    print(f"PASS {label}", flush=True)


class JobFailure(Exception):
    pass


@contextmanager
def register(outer_id, scope, mode=0o400):
    with tempfile.NamedTemporaryFile(mode="w", dir=REGISTRATION.parent, delete=False) as record:
        staging = Path(record.name)
        try:
            record.write(f"{outer_id} {scope}\n")
            record.flush()
            os.fchmod(record.fileno(), mode)
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
    mode.add_argument("--native-results", type=Path,
                      help="JSON results from the unmodified baseline runtime")
    args = parser.parse_args()
    lab = args.lab.resolve(strict=True)
    if (os.geteuid() != 0 or os.environ.get("DOCKER_HOST") != f"unix://{lab}/docker.sock"
            or not Path("/run/sysbox").samefile(lab / "run-sysbox")
            or REGISTRATION.exists() or REGISTRATION.is_symlink()):
        parser.error("requires the disposable daemon, its private Sysbox mount, and no previous registration")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", args.image):
        parser.error("use a pinned local image ID")

    probe = args.probe.resolve(strict=True)
    # An existing OCI filter should take precedence even with registration.
    # A distinct errno shows the active response came from that filter.
    seccomp = lab / "deny-compatibility.json"
    seccomp.write_text(json.dumps({
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [
            {"names": ["perf_event_open", "bpf"], "action": "SCMP_ACT_ERRNO",
             "errnoRet": errno.EACCES},
        ],
    }))
    try:
        if args.baseline_only:
            with test_container("sysbox-baseline", args.image, probe, lab) as (_, _, baseline):
                native = snapshot(baseline)
            with test_container("sysbox-baseline", args.image, probe, lab, seccomp) as (_, _, denied):
                blocked = snapshot(denied)
            print(json.dumps({"native": native, "blocked": blocked}), flush=True)
            return

        results = json.loads(args.native_results.read_text())
        native, blocked = results["native"], results["blocked"]
        require(native["ordinary-perf"] == [0], "ordinary perf succeeds natively")
        require(native["probe"] != [0], "native Cilium perf request needs delegation")
        require(len(native["jit"]) == 13, "native socket-filter metadata is readable")
        require(all(result == [errno.EACCES] for result in blocked.values()),
                "OCI seccomp fixture returns EACCES on the baseline")
        with ExitStack() as stack:
            active_args = ("sysbox-standard", args.image, probe, lab)
            outer, scope, active = stack.enter_context(test_container(*active_args))
            other_outer, other_scope, other = stack.enter_context(test_container(*active_args))
            denied_outer, denied_scope, denied = stack.enter_context(test_container(*active_args, seccomp))
            require(scope != other_scope, "jobs occupy different cgroups")
            compare_native(active, native, "missing registration")
            with register(outer, scope, mode=0o420):
                compare_native(active, native, "invalid registration permissions")
            with register(other_outer, scope):
                compare_native(active, native, "wrong container ID")
                compare_native(other, native, "registered ID with wrong cgroup")
            with register(denied_outer, denied_scope):
                compare_native(denied, blocked, "OCI seccomp denial with valid registration")

            for failing in (False, True):
                try:
                    with register(outer, scope):
                        require(probe_result(active, "probe") == [0],
                                "registered request opened a usable perf ring")
                        jit = probe_result(active, "jit")
                        require(len(jit) == 13 and jit[1:3] == native["jit"][1:3] and
                                jit[3] > native["jit"][3] and jit[4] == 0 and
                                jit[5:] == native["jit"][5:],
                                "registered JIT response adds only the allowed feature metadata")
                        compare_native(active, native, "registered caller outside compatibility scope",
                                       ("ordinary-perf", "out-of-policy", "jit-unsupported"))
                        compare_native(other, native, "other job during registration")
                        if failing:
                            raise JobFailure()
                except JobFailure:
                    pass
                label = "failed job" if failing else "successful job"
                require(not REGISTRATION.exists(), f"{label} registration removed")
                compare_native(active, native, f"{label}: same live requester after removal")
    finally:
        seccomp.unlink()


if __name__ == "__main__":
    main()
