# Cilium compatibility / Cilium 互換性

## Contents / 目次

- [English](#english)
- [日本語](#日本語)

## English

### Standard build and host requirements

`python3 scripts/build.py` applies the proc, sysfs, FUSE, and Sysbox Cilium
compatibility patches to the pinned v0.7.1 sources. It tests default routing,
registration scope, the perf event target and arguments, and both JIT probes.
Install `sysbox-fs` and `sysbox-runc` from the same manifest alongside the two
mount helpers. The pair routes the supported calls without
`SYSBOX_EXPERIMENT_PERF_OUTPUT`. Keep the existing OCI seccomp policy in place.
A denial in that policy takes precedence, so the intended workload must already
use a profile that admits these notifications. Native amd64 and arm64 callers
are eligible for delegation. Other ABIs retain kernel behavior for these calls.

The host must prepare cgroup v2, the delegated bpffs and BPF token used by the
Cilium workload, and the registered cgroup scope. A trusted host process writes
the root-owned, non-group/world-writable regular file
`/run/sysbox/perf-output-lab`. Each line contains the full outer Sysbox
container ID and its authorized absolute cgroup path. Register the job's
cgroup, then remove the entry at job completion. The kernel must support
seccomp user notifications, the continue and FD-injection operations, and
cgroup-scoped perf events.

Requests outside an authorized cgroup or supported request shape continue in
the kernel. A delegated perf event is active only while a task in the registered
cgroup subtree runs on the event CPU. The checks below verify the target FD,
event flags, and ring setup. They do not measure event delivery. Removing a
registration returns subsequent requests to native behavior. FDs already issued
follow the kernel's lifetime rules. Cilium JIT probe responses are limited to
the documented scalars. The XDP probe response leaves the instruction buffer
untouched.

### Disposable runtime comparison

Use a disposable Sysbox setup with private mount and daemon state,
`$lab/run-sysbox` mounted at `/run/sysbox`, and an independent Docker daemon
at `unix://$lab/docker.sock`. Install the matching binaries and helpers from
the standard build in the candidate setup. Keep an unmodified runtime and FS
pair for the baseline. Register the two runtime names in their respective
daemon configurations.

- `sysbox-baseline` invokes the original runtime with the original FS daemon.
- `sysbox-standard` invokes the standard build with its matching FS daemon.

Use the same pinned local image and probe for both runs. The comparison host
must allow a native caller to open a per-thread software perf event, and the
CPU-wide Cilium request must need delegation. Run each command inside its
respective disposable environment with its own `DOCKER_HOST`.

```sh
python3 scripts/build.py
cc -O2 -Wall -Wextra -Werror -static -o ./dist/perf-probe tests/runtime/cilium-lab-perf.c

# Original pair
python3 tests/runtime/cilium-lab-perf.py "$lab" "$image_id" "$probe" --baseline-only > "$native_results"

# Standard pair with SYSBOX_EXPERIMENT_PERF_OUTPUT absent
python3 tests/runtime/cilium-lab-perf.py "$lab" "$image_id" "$probe" --native-results "$native_results"
```

The harness compares native perf results and BPF visibility when registration
is missing, invalid, assigned to a different job, or removed. It checks
unsupported requests from a registered caller and an existing OCI seccomp
denial. The registered perf request must open a close-on-exec FD and a usable
ring. The live JIT check uses a fixed, unattached socket-filter probe. XDP
response checks run in the Go unit tests. Record the architecture, kernel and
Sysbox versions, SHA-256 of the two components launched on each side, the
tested revision, and any checks that could not run.

### Cilium warnings

The earlier Cilium 1.20.4 run on Linux 6.18.44 (amd64) made both agents Ready and
passed all five catalog network cases. The same run logged these two warnings. The later [catalog kind job on the NixOS
runner](https://github.com/michibiki-io/kubara-catalogs/actions/runs/45242975883/job/137935137286)
passed all 13 tests with the stock v1.20.4 Agent and the test capability settings.
That run used the earlier Sysbox configuration and did not include the two
warning-specific recovery checks below.

| Warning | Effect established from the Cilium source | Test coverage |
| --- | --- | --- |
| TCX ingress `BPF_PROG_QUERY` failed in the endpoint BPF watchdog | On a query error the watchdog returns before it can decide whether to reload the missing programs. [Endpoint watchdog](https://github.com/cilium/cilium/blob/v1.20.4/pkg/endpoint/watchdog/ep-bpfprog-watchdog.go) | Normal datapath, DNS, and BGP tests passed. Recovery after detaching an endpoint program was not exercised. |
| `BPF_PROG_TYPE_TRACING` failed when starting the socket termination job | Failure to create the destroyer prevents the loop from monitoring deleted or unhealthy backends and terminating their existing TCP and UDP sockets. [Socket termination job](https://github.com/cilium/cilium/blob/v1.20.4/pkg/loadbalancer/reconciler/termination.go) | Endpoint deletion and BGP withdrawal passed. Forced termination of an established socket to a removed backend was not exercised. |

### Separate Cilium patch for the warnings

[The warning patch](../patches/cilium-v1.20.4-warning-lab.patch) applies to
[Cilium v1.20.4 at the recorded commit](https://github.com/cilium/cilium/tree/beb276d2f38d4aadfda14710acf8d14a0f1ba723).
Its input is a clean Cilium checkout. Run the following from this repository with
`cilium_source` set to the checkout's absolute path. Apply the patch only to a
disposable checkout.

```sh
test "$(git -C "$cilium_source" rev-parse HEAD)" = beb276d2f38d4aadfda14710acf8d14a0f1ba723
git -C "$cilium_source" apply --check "$PWD/patches/cilium-v1.20.4-warning-lab.patch"
git -C "$cilium_source" apply "$PWD/patches/cilium-v1.20.4-warning-lab.patch"
mkdir -p dist/cilium-warning/.go-cache
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
  -v "$cilium_source:/src:ro" -v "$PWD/dist/cilium-warning:/out" -w /src \
  -v "$PWD/dist/cilium-warning/.go-cache:/cache" -e GOCACHE=/cache \
  -e CGO_ENABLED=0 -e GOMAXPROCS=4 \
  docker.io/library/golang@sha256:2005724102f45917a63e9d092fc0e4ea56ea575048ce147caad5f5f61502c365 \
  go build -p 4 -mod=vendor -buildvcs=false \
  -ldflags '-s -w -X "github.com/cilium/cilium/pkg/version.ciliumVersion=1.20.4 beb276d2f38d4aadfda14710acf8d14a0f1ba723 2026-10-23"' \
  -o /out/cilium-agent ./daemon
sha256sum patches/cilium-v1.20.4-warning-lab.patch dist/cilium-warning/cilium-agent
```

In the disposable two-node catalog environment, place the trial binary on both
kind nodes, mount it read-only in the Agent container, and use it as that
container's command with the original args. Make the same experiment-only
DaemonSet override in the bootstrap, VTEP, and GitOps exports so that each
catalog test uses the same Agent. The Sysbox setup above supplies the same
BPF token and perf/JIT authorization.

- For TCX, select a disposable veth endpoint on each node. Read the ID and
  ifindex of its Cilium-owned ingress link under the endpoint's bpffs link
  directory. Remove only that test endpoint's pin. Wait for the watchdog to
  install a different link ID on the same ifindex, then check connectivity.
- For socket termination, create two test Services with connected UDP clients
  and separate healthy backends. Change one Service's selector to remove
  its original backend while keeping that Pod alive. Verify that its original
  connected socket is aborted and the other Service's connected client still
  receives responses. Require the Agent to log selection of the existing
  Netlink implementation after BPF initialization returned `EPERM`. The
  additional fallback leaves `EACCES` as an error.

On amd64, Linux 6.18.44 and Sysbox 0.7.1, the watchdog installed a different
TCX link ID at the same ifindex on both kind nodes, and connectivity recovered.
The Service reconciler terminated the target UDP socket while the control
connection and old backend Pod stayed up. All seven tests passed in 254.51 seconds. The TCX
check exercised veth endpoints. The standard Sysbox release recipe does not
consume this patch.

| Trial evidence | SHA-256 |
| --- | --- |
| Cilium source patch | `c9918be5c8a4d4afa256ae9838b0fa2c3878805cc5dcfe50d3dc1850c04cac74` |
| Built Cilium Agent exercised on both nodes | `2a2d95582e0eca8e52e98e24db87fc0da22dcae614f4528fc55feaf0edf14364` |
| Local test log | `07fa6914393d0238d7145a5fe74899b8a4a3a6d486327a671a84e6aeff66c034` |

## 日本語

### 標準ビルドとホスト側の前提

`python3 scripts/build.py` は固定した v0.7.1 のソースに proc、sysfs、
FUSE、Sysbox の Cilium 互換パッチを適用します。既定の通知設定、登録範囲、
perf イベントに渡す引数と cgroup、JIT プローブ 2 種をテストします。
`sysbox-fs` と `sysbox-runc` はマウント用ヘルパーと同じ manifest
に記録されたバイナリを導入してください。
`SYSBOX_EXPERIMENT_PERF_OUTPUT` の設定は不要です。既存の OCI seccomp
による拒否は Sysbox の通知より優先されます。ワークロードには対象の通知を許す
既存のプロファイルを使います。委譲は amd64 と arm64 のネイティブ ABI が対象です。
ほかの ABI では対象の呼び出しをカーネルに委ねます。

ホストには cgroup v2、Cilium 用に委譲する bpffs と BPF token が必要です。
ジョブの実行環境を管理するホストプロセスが、コンテナの完全な ID と
cgroup の絶対パスを `/run/sysbox/perf-output-lab` に 1 行ずつ登録し、
ジョブ終了時にその登録を削除します。登録には root 所有の通常ファイルを使い、
グループとその他のユーザーには書き込み権限を与えません。カーネルには
seccomp 通知、通知の継続と FD の受け渡し、cgroup 単位の perf イベントが必要です。

登録対象外の要求と、対応範囲外の要求はカーネルに委ねます。委譲された perf
イベントは、登録した cgroup またはその子孫のタスクが対象 CPU で実行されている間に
有効になります。以下の確認は対象 FD、フラグ、リングの取得までを検証します。
イベントの到達は検証範囲に含みません。登録削除後の要求はカーネルに委ね、
すでに発行した FD の寿命はカーネルの仕様に従います。XDP には変換後の
命令列の長さを返し、命令バッファには書き込みません。

### 使い捨て環境での比較

上記のコマンドを、プライベートなマウントと独立した Docker デーモンを持つ
使い捨て環境で実行します。同じイメージと probe で、未改変のペアと
標準ビルドのペアを比較します。未改変側では、スレッド単位の通常の perf
イベントを開けることと、CPU 全体を対象とする Cilium の要求に委譲が必要なことを
確認します。登録なし、登録不正、別ジョブ、正常終了と失敗による登録削除後を
比較します。登録済みの呼び出し元による対象外の要求と、既存の OCI seccomp
による拒否も確認します。実機 JIT テストでは固定の socket-filter を使います。
XDP の応答は Go の単体テストで確認します。アーキテクチャ、カーネルと
Sysbox の版、両側で起動したバイナリの SHA-256、対象リビジョン、未実施項目を
記録します。

### Cilium の警告

Linux 6.18.44 の amd64 環境で Cilium 1.20.4 の両 Agent が Ready になり、
カタログのネットワークテスト 5 件が通りました。その後の
[NixOS runner の kind ジョブ](https://github.com/michibiki-io/kubara-catalogs/actions/runs/45242975883/job/137935137286)
では、未改変の v1.20.4 Agent とテスト用の capability 設定で 13 件すべてが
通りました。この結果は以前の Sysbox 構成で得たもので、以下の警告に固有の
復旧試験は含みません。最初の実行では、TCX
アタッチの照会に失敗すると watchdog がプログラムの再ロード要否を
判定できませんでした。また、トレーシングプログラムをロードできず、
削除・異常バックエンドへの既存ソケットを強制終了するジョブが起動しませんでした。
手動でデタッチしたプログラムの自動修復と、削除したバックエンドへの
既存ソケットの強制終了は未検証です。

### 警告に対応する Cilium 側の試験パッチ

上記の手順で、固定した Cilium v1.20.4 に試験パッチを適用して Agent を
ビルドできます。使い捨て kind の両ノードに Agent を配置し、bootstrap、
VTEP、GitOps の各出力で同じ Agent を参照しました。

- TCX は、Cilium 自身がピン留めしたリンクを使ってアタッチ状態を照合します。
  テスト用 veth endpoint のピンを外し、watchdog が同じ ifindex に別の
  リンクを作って通信が戻ることを両ノードで確認しました。
- ソケット終了処理は、Netlink の機能プローブが成功し、BPF の初期化で
  `EPERM` になった場合に、既存の Netlink 実装に切り替えます。
  `EACCES` は従来どおりエラーとして返します。
  Service のバックエンドを外すと、元の Pod は稼働したまま既存 UDP
  ソケットが終了し、対照の通信が続くことを確認しました。

amd64、Linux 6.18.44、Sysbox 0.7.1 の使い捨て環境で、上記 2 件と
既存のカタログネットワークテスト 5 件が通りました。実行時間は 254.51 秒です。
TCX の実機検証は veth、Service 経由のソケット終了の実機検証は UDP が対象です。
