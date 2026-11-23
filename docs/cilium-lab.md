# Cilium compatibility experiment / Cilium 互換性の試験

## Contents / 目次

- [English](#english)
- [日本語](#日本語)

## English

### Build and focused tests

The release recipe still applies only the proc, sysfs, and FUSE patches. The Cilium
lab build applies a fourth patch to the pinned Sysbox sources and builds a separate
`sysbox-fs` and `sysbox-runc` pair. It runs the Go tests for registration scope, perf
attributes, and the two JIT responses, and writes input and output hashes to
`manifest.json`.

From this repository, with an initialized Sysbox v0.7.1 checkout and its pinned
submodules available at `$sysbox_source`:

```sh
python3 scripts/build-cilium-lab.py "$sysbox_source" --check-only
python3 scripts/build-cilium-lab.py "$sysbox_source" --output ./dist/cilium-lab
cc -O2 -Wall -Wextra -Werror -static -o ./dist/cilium-lab/perf-probe tests/runtime/cilium-lab-perf.c
```

Use a disposable Sysbox installation on cgroup v2. Set up a private mount namespace
with `$lab/run-sysbox` mounted on `/run/sysbox`, separately mounted Sysbox state,
and an independent Docker daemon on `unix://$lab/docker.sock`. Use the existing
paired helpers with the lab binaries. Register the following runtime names in
the disposable daemon.

- `sysbox-baseline` invokes the original Sysbox runtime. Run the baseline with the original Sysbox FS daemon.
- `sysbox-lab-off` invokes the lab runtime without the environment variable below.
- `sysbox-lab` invokes the lab runtime through a host-owned wrapper that sets `SYSBOX_EXPERIMENT_PERF_OUTPUT=1`. The two lab runtime names use the lab Sysbox FS daemon.

Use the same local image ID and static probe binary for both runs. Run the
following commands in their respective private mount namespaces with
`DOCKER_HOST` pointing to each disposable daemon.

```sh
# With the original FS daemon, save stdout as the native result.
python3 tests/runtime/cilium-lab-perf.py "$lab" "$image_id" "$probe" --baseline-only

# With the lab FS daemon, pass that recorded result as native_result.
python3 tests/runtime/cilium-lab-perf.py "$lab" "$image_id" "$probe" --native-perf "$native_result"
```

The perf test starts two live contenders under the experiment and one with routing
disabled. It compares disabled behavior to the original runtime, checks that the
enabled path rejects a missing or mismatching registration, and verifies that an
eligible request opens a close-on-exec FD with a usable perf ring. It removes the
registration after both a successful and a deliberately failed job while the same
requester stays alive. Removal blocks subsequent requests. FDs already issued
remain subject to the kernel's existing lifetime rules.

The JIT tests check the returned bytes for the socket-filter and XDP probes and
the rejection of other program types and tags. XDP may ask for a translated
instruction buffer, but the lab returns a scalar length and leaves that buffer
untouched. Native BPF behavior applies outside the lab authorization.

### Cilium warnings

The earlier Cilium 1.20.4 run on Linux 6.18.44 (amd64) made both agents Ready and
passed all five catalog network cases. The same run logged these two warnings.

| Warning | Effect established from the Cilium source | Test coverage |
| --- | --- | --- |
| TCX ingress `BPF_PROG_QUERY` failed in the endpoint BPF watchdog | On a query error the watchdog returns before it can decide whether to reload the missing programs. [Endpoint watchdog](https://github.com/cilium/cilium/blob/v1.20.4/pkg/endpoint/watchdog/ep-bpfprog-watchdog.go) | Normal datapath, DNS, and BGP tests passed. Recovery after detaching an endpoint program was not exercised. |
| `BPF_PROG_TYPE_TRACING` failed when starting the socket termination job | Failure to create the destroyer prevents the loop from monitoring deleted or unhealthy backends and terminating their existing TCP and UDP sockets. [Socket termination job](https://github.com/cilium/cilium/blob/v1.20.4/pkg/loadbalancer/reconciler/termination.go) | Endpoint deletion and BGP withdrawal passed. Forced termination of an established socket to a removed backend was not exercised. |

## 日本語

### ビルドと個別テスト

通常のリリースビルドには既存 3 パッチを適用します。試験用ビルドには
Cilium 用のパッチも適用し、`sysbox-fs` と `sysbox-runc` を別に出力します。
登録範囲、perf 属性、JIT プローブ 2 種を Go テストで検証し、入出力の
ハッシュを `manifest.json` に記録します。

上記のコマンドで、固定した Sysbox v0.7.1 ソースへの適用確認、試験ビルド、
perf テストのコンパイルを実行できます。実機テストは cgroup v2 の
使い捨て環境で実行します。まず元のバイナリでネイティブの結果を取り、
試験用バイナリでは通知無効時の結果が一致することを確認します。
通知を有効にすると、登録済みの cgroup で perf FD を開いてリングを
`mmap` できます。未登録と別ジョブからの要求、対象外の属性は拒否します。
登録削除は正常終了と制御された失敗で試し、同じプロセスからの再要求が
拒否されることを確認します。すでに発行された FD の寿命はカーネルに従います。

JIT の個別テストでは socket filter と XDP の応答をバイト単位で比較し、
異なるプログラム種別やタグを拒否することを確認します。XDP には変換後の
命令列の長さだけを返し、命令バッファには書き込みません。

### Cilium の警告

Linux 6.18.44 の amd64 環境で Cilium 1.20.4 の両 Agent が Ready になり、
カタログのネットワークテスト 5 件が通りました。同じ実行では、TCX
アタッチの照会に失敗すると watchdog がプログラムの再ロード要否を
判定できませんでした。また、トレーシングプログラムをロードできず、
削除・異常バックエンドへの既存ソケットを強制終了するジョブが起動しませんでした。
手動でデタッチしたプログラムの自動修復と、削除したバックエンドへの
既存ソケットの強制終了は未検証です。
