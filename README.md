# Sysbox Compatibility / Sysbox 互換性

## Table of Contents / 目次

- [English](#english)
  - [Overview](#overview)
  - [Build](#build)
  - [Installation](#installation)
  - [Sysfs opt-in](#sysfs-opt-in)
  - [Cilium compatibility](#cilium-compatibility)
  - [Verify](#verify)
  - [Documentation](#documentation)
  - [License](#license)
- [日本語](#日本語)
  - [概要](#概要)
  - [ビルド](#ビルド)
  - [導入](#導入)
  - [sysfs の有効化](#sysfs-の有効化)
  - [Cilium 互換機能](#cilium-互換機能)
  - [検証](#検証)
  - [関連文書](#関連文書)
  - [ライセンス](#ライセンス)

## English

### Overview

Formerly Sysbox proc transfer, this source-only repository provides compatibility patches and C helpers for pinned Sysbox v0.7.1. The standard build includes procfs transfer, opt-in sysfs transfer and network-view FUSE repair, FUSE overlay mount compatibility, and narrowly scoped Cilium perf/JIT compatibility.

Procfs transfer lets an unchanged, unprivileged-user bubblewrap `--proc /proc` invocation create procfs for its sandbox PID namespace. It preserves registered masks, read-only protections and User/PID/Mount isolation, including nonleader requests (Issue #3); outer read-only policy is normalized before nested dispatch. The transfer requires registered UID/GID maps, a direct child User namespace owning the target Mount/PID namespaces, and kernel support for procfs `pidns`, pidfds and the new mount APIs. These features do not grant general host mount or BPF permissions. See the [security model](docs/security-model.md) and [verification boundaries](docs/compatibility.md#verification-boundaries) for scope and limits; this is not a full security audit.

### Build

Prerequisites on the build client are Python 3 and Docker CLI with a working buildx/BuildKit builder. No host compiler, Go toolchain or existing Sysbox checkout is needed. All compilation and package installation occur in the builder. Public upstream inputs are fetched over HTTPS.

```sh
python3 scripts/build.py
# Optional single target platform, if the builder supports it:
python3 scripts/build.py --platform linux/arm64 --output dist
```

The default is a native build. `dist/` receives the four statically linked binaries `sysbox-fs`, `sysbox-runc`, `proc-mount-helper`, `sysfs-mount-helper`, and `manifest.json` using BuildKit local output from a scratch stage. The manifest records the output ELF architecture, component revisions, builder digest, generator version and input/output SHA-256 hashes without machine identities or local paths.

[build/sources.lock.json](build/sources.lock.json) is the authoritative pin source. The wrapper supplies its values as Docker build arguments, checks source integrity hashes, and the builder checks root/component commits after recursive submodule initialization. IPC protobuf generation with `protoc-gen-go` v1.3.5 runs before building `sysbox-fs`. A focused upstream-package regression test verifies read-only policy normalization before nested dispatch without executing a helper or changing mounts. The patches retain upstream component paths and are applied at the Sysbox root. The namespace-entry C code is linked into `sysbox-fs`. The bundled `sysbox-runc` supplies the Cilium notifications.

Pinned inputs and recorded hashes do not establish byte-identical rebuilds. Builder apt repositories and upstream Go module availability remain external dependencies. A successful build on another architecture is compilation evidence only, not runtime validation. This repository publishes source, not binaries.

For nested rootful Docker on `fuse-overlayfs`, configure both paired helpers, `SYSBOX_PROC_TRANSFER_HELPER` and `SYSBOX_SYSFS_TRANSFER_HELPER`, on a [supported kernel](docs/compatibility.md). The lookup worker opens targets with the notifying thread’s filesystem credentials in its User and Mount namespaces and keeps the descriptor through protected mounts. Supply `/dev/fuse` to the outer container and keep the kernel’s default FUSE access setting.

### Installation

Deploy the matching `sysbox-fs` and `sysbox-runc` pair and both helpers from one manifest; use upstream `sysbox-mgr`, which is not a build output. Configure the OCI runtime entry to use the patched `sysbox-runc`, retaining host-specific wrapper settings. Set `SYSBOX_PROC_TRANSFER_HELPER` in the `sysbox-fs` daemon environment to the trusted proc helper's absolute installed path; unset preserves upstream proc dispatch. Protect both helper executables and the daemon environment from container callers. Host deployment is outside this repository.

The separate [sysbox-compat-nix v0.3.0 package](https://github.com/michibiki-io/sysbox-compat-nix/tree/v0.3.0) provides the canonical Flake output `sysbox-compat` for `aarch64-linux` and `x86_64-linux`; `default`, `sysbox-proc-transfer` and `sysbox-cilium-lab` are aliases. Its Sysbox proc transfer NixOS module selects the daemon and proc helper; configure the runtime separately. Follow the [NixOS instructions](https://github.com/michibiki-io/sysbox-compat-nix/blob/v0.3.0/README.md#use-with-nixos) and pin the full packaging commit. The daemon/runtime need their Nix store closure; both helpers (`bin/proc-mount-helper` and `bin/sysfs-mount-helper`) are statically linked. Native package CI checks builds and focused tests, not full runtime support.

### Sysfs opt-in

Issue #5 adds a separate opt-in sysfs path. Set the trusted daemon environment `SYSBOX_SYSFS_TRANSFER_HELPER` to the absolute path of `sysfs-mount-helper`. Unset preserves upstream sysfs dispatch. The proc helper source and FD protocol remain unchanged. Enabled registration requires a visible `/sys` mount and readable protection metadata; transfer requires a `sysfs` mount at `/sys` with mountinfo Root `/` and a real `/tmp` directory in the outer rootfs. See [filesystem compatibility](docs/compatibility.md#sysfs-consumer-gate).

Use [runtime instructions](tests/runtime/README.md#new-sysfs-and-network-checks) for the new nonleader sysfs probe and direct lifecycle fixture. Preserve all outer masks/read-only mounts and the original bwrap proc and `/sys` bind checks. Acceptance of new sysfs mounts and FUSE repair is independent of proc transfer acceptance. Production helpers never accept test checkpoint sockets. No installer, host daemon or cluster changes are supplied.

### Cilium compatibility

The standard v0.7.1 Sysbox build includes the Cilium perf output and JIT probe handlers; `SYSBOX_EXPERIMENT_PERF_OUTPUT` is not required. The host must provide cgroup v2, delegated bpffs and a BPF token, and per-job cgroup registration with cleanup. Existing OCI seccomp denials take precedence; authorization and supported request shapes are limited to the documented native amd64/arm64 cases. Out-of-scope requests retain kernel behavior. Perf checks establish FD and ring setup, not event delivery; JIT responses are limited to documented scalars. For kind, prepare delegated bpffs and writable `/etc/sysctl.d` before Cilium init containers run. See [standard build and host requirements](docs/cilium-lab.md#standard-build-and-host-requirements).

The separate, optional `cilium-warning-agent` Nix output is a standalone Cilium v1.20.4 Agent for disposable TCX recovery and socket termination tests. It is not part of the standard Sysbox build or required for stock Agent use. See [warning-specific test procedure](docs/cilium-lab.md#separate-cilium-patch-for-the-warnings) and the [Nix package instructions](https://github.com/michibiki-io/sysbox-compat-nix/blob/v0.3.0/README.md#optional-cilium-warning-agent).

### Verify

Focused local checks require Python 3, Bash and a C compiler with Linux headers:

```sh
python3 -m unittest discover -s tests/static -v
```

Runtime verification runs **inside an already provisioned Sysbox container**, as its existing non-root caller. Preinstall `cc`, `/usr/bin/python3` and bubblewrap; scripts install nothing. Supply the actual host PID and User namespace identifiers, obtained independently by the operator, as positional inputs (the `pid:[number]` and `user:[number]` forms returned by `readlink`). Do not derive those inputs from inside the container.

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
# Optional separate stress check in the same container:
python3 tests/runtime/stress-proc.py
```

The verification script uses a caller-owned `mktemp` directory with exit cleanup and paths relative to the script. It checks the original bwrap command, sandbox PID identity, seccomp, registered protection identities, masks, read-only flags, detach denial and recursive read-only procfs. Its `/sys` check covers the preserved tree bound by `--ro-bind /sys /sys`; it does not test a new nested sysfs mount fix. The optional stress case exercises 500 unchanged bwrap mounts with eight workers and concurrent nsenter/FUSE reaping. Runtime results and namespace identifiers are local diagnostics; do not publish raw operational logs.

The existing negative helper tests run from the trusted launcher environment and create only their own disposable sandbox via an operator-supplied container-exec prefix. Python 3.12+ and root access to namespace metadata are required for this harness. It never configures or restarts a daemon. Select one rejection case per invocation; use a dedicated test container.

```sh
python3 tests/runtime/helper-rejections.py \
  --outer-pid "$OUTER_INIT_PID" --helper "$TRUSTED_HELPER" \
  --uid "$CALLER_UID" --gid "$CALLER_GID" --mode wrong-owner \
  --exec docker exec --user "$CALLER_UID:$CALLER_GID" test-container
```

Other modes are `dead-requester`, `unsupported-flags`, and `mapped-launcher`. `OUTER_INIT_PID` must identify the registered outer container in the launcher's proc view. The script locates and kills only its uniquely tagged sandbox through a pinned pidfd; it does not use a supplied arbitrary target PID. Mount work inside the helper continues to use the mapped outer User namespace.

The runner also checks nonleader TID != TGID mounts in distinct Mount namespaces, with an independent observer and all visible registered proc submounts. For deterministic exit/invalidation/exec race cases, compile and run the trusted test-only checkpoint harness described in [design](docs/design.md) and [runtime commands](tests/runtime/README.md). Thread pidfds require `PIDFD_THREAD`; unsupported acquisition returns the original errno and never falls back to a TGID or an unprotected mount.

CI runs focused checks and a native container build from public inputs. It does not run the supported Sysbox runtime environment. Historical runtime evidence is revision-specific:

- Procfs: the updated pair passed nonleader and lifecycle checks on 2026-10-14; the corrected verifier passed on 2026-10-16, both on arm64/Linux 7.1.0/Sysbox 0.7.1/bubblewrap 0.9.0. Actual kernels missing the optional proc entries remain untested.
- New sysfs and FUSE network view: supplemental arm64/Linux 7.1 tests passed on 2026-10-15 with the initial sysfs pair. Later pairs have narrower recorded results. The unchanged downstream v0.4.1 suite failed at interleave after eight fresh-sysfs cases; later checks were unrun. Portable oracle corrections are not a new runtime pass. **AC7 remains deferred/unrun on genuine amd64/6.18.18-talos, Sysbox 0.7.1 and bwrap 0.12.0 until talos-sysbox-installer integration.**
- FUSE overlay: the initial candidate passed nested Docker 27.5.1 with `fuse-overlayfs` on amd64/Linux 6.18.64 and arm64/Linux 7.1.0, with Sysbox 0.7.1 and default FUSE access. Stock BuildKit v0.35.1 failed the SBOM case on both; the test-only patched worker passed. Real Talos and release-sized performance comparison are unrun.
- Cilium: the earlier stock v1.20.4 Agent run on amd64/Linux 6.18.44 passed five catalog network cases; a later NixOS catalog job passed 13 with the earlier Sysbox configuration, not the warning-specific checks. The separate warning Agent passed seven tests on amd64/Linux 6.18.44/Sysbox 0.7.1. Use the [disposable runtime comparison](docs/cilium-lab.md#disposable-runtime-comparison) for perf/JIT verification of the standard pair.

See [compatibility](docs/compatibility.md) for exact historical hashes, conditions and limits; record PASS/FAIL/UNRUN for the actual tested revision.

### Documentation

- [Design](docs/design.md): procfs transfer flow and the internal daemon/helper contract.
- [Security model](docs/security-model.md): authorization, namespace isolation and registered procfs protections.
- [Compatibility](docs/compatibility.md): validated conditions, review correction checks and remaining limitations.
- [Cilium compatibility](docs/cilium-lab.md#english)
- [Runtime verification commands](tests/runtime/README.md#english)

### License

Original helper, validation, build tooling and documentation use the root [MIT license](LICENSE). The Sysbox portions of the patches, separate Cilium warning patch and test-only BuildKit patch are Apache-2.0 derivatives; the pinned FUSE-library change retains its [BSD notice](LICENSES/bazil-fuse.txt). Upstream attribution and license are retained in [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Static binary redistribution requires separate third-party license review, including applicable LGPL obligations; root MIT does not cover every linked dependency.

## 日本語

### 概要

旧称 Sysbox proc transfer の本リポジトリは、固定した Sysbox v0.7.1 向けの互換パッチと C 製の補助プログラム（helper）のソースを公開します。
標準ビルドには procfs 転送、任意で有効にする sysfs 転送とネットワーク表示用の FUSE 修正、FUSE overlay マウントの互換機能、および対象を限定した Cilium の perf/JIT 互換機能が含まれます。

一般ユーザーの bubblewrap 呼び出しを変更せず、`--proc /proc` で sandbox 自身の PID 名前空間に対応する procfs を作成します。
レビューで判明した読み取り専用属性の継承漏れを修正し、既存の判定を入れ子の名前空間への転送前に適用します。
その他の検証済み処理は維持しています。
登録済みの procfs 保護と User/PID/Mount 名前空間の隔離を維持します。
転送には登録済み UID/GID map、対象の Mount/PID 名前空間を所有する直下の子 User 名前空間、procfs の `pidns`、pidfd、新しい mount API に対応するカーネルが必要です。
検証済みの基準環境は arm64、Linux 7.1、Sysbox 0.7.1、bubblewrap 0.9.0 です。
Issue #3 は実際の TID の thread pidfd と FD 固定後の通知確認により、非 leader の要求に対応する処理を実装します。
更新した対は arm64 の実行時検証で、非 leader の mount と決定的な commit の競合検査を通過しました。
証跡と検証範囲は [動作条件](docs/compatibility.md) に記載します。
ホストのマウントや BPF の権限を一般に付与する機能ではありません。
[安全性の設計](docs/security-model.md) と [検証範囲](docs/compatibility.md#検証範囲) を参照してください。完全な安全性監査を意味しません。

### ビルド

ビルドを実行するクライアントには Python 3 と Docker CLI が必要です。
Docker CLI から buildx/BuildKit のビルダーを利用できるように構成します。
ホストに C コンパイラーや Go ツールチェーン、既存の Sysbox チェックアウトを用意する必要はありません。
コンパイルとパッケージの導入はビルダー内で行い、公開されている upstream の入力を HTTPS で取得します。

```sh
python3 scripts/build.py
# ビルダーが対応する場合、単一の対象プラットフォームを指定できます。
python3 scripts/build.py --platform linux/arm64 --output dist
```

既定ではビルダーのネイティブアーキテクチャ向けにビルドします。
scratch ステージから BuildKit のローカル出力を使い、`dist/` に静的リンクした4つのバイナリ `sysbox-fs`、`sysbox-runc`、`proc-mount-helper`、`sysfs-mount-helper` と `manifest.json` を出力します。
manifest は ELF のアーキテクチャ、コンポーネントのリビジョン、ビルダーのダイジェスト、生成器のバージョン、入出力の SHA-256 を記録します。
マシン識別情報やローカルパスは含めません。

[対応カーネル](docs/compatibility.md)で入れ子の rootful Docker に `fuse-overlayfs` を使う場合は、同じビルドの `SYSBOX_PROC_TRANSFER_HELPER` と `SYSBOX_SYSFS_TRANSFER_HELPER` を設定します。通知元スレッドの User・Mount 名前空間とファイルシステム資格情報で対象を開き、保護付きマウントまで FD を保持します。外側コンテナに `/dev/fuse` を渡し、カーネルの FUSE アクセス設定は既定値を使用します。

固定値の正本は [build/sources.lock.json](build/sources.lock.json) です。
ビルドスクリプトは固定値を Docker のビルド引数に渡し、ソースの整合性をハッシュで確認します。
ビルダーはサブモジュールを再帰的に初期化した後、ルートと各コンポーネントのコミットを確認します。
`protoc-gen-go` v1.3.5 による IPC protobuf 生成を `sysbox-fs` のビルドより先に実行します。
upstream パッケージ内の回帰テストで、helper の実行や mount の変更なしに、入れ子の名前空間を扱う分岐より前の読み取り専用属性の継承を確認します。
パッチは upstream のコンポーネントパスを保持し、Sysbox のルートディレクトリで適用します。
名前空間に入る処理の C コードは `sysbox-fs` にリンクします。標準ビルドの `sysbox-runc` は Cilium 用の通知を設定します。

入力の固定とハッシュの記録だけでは、再ビルド時にバイト単位で一致することを保証できません。
ビルダーの apt リポジトリと upstream の Go モジュールの可用性は外部依存です。
別のアーキテクチャでのビルド成功はコンパイルの確認であり、実行時の検証ではありません。
このリポジトリではソースを公開し、バイナリは公開しません。

### 導入

同じ manifest の `sysbox-fs` と `sysbox-runc` の対、および両方の helper を導入します。
`sysbox-mgr` は上流版を使い、ビルドの出力には含めません。
ホスト固有のラッパー設定を保持し、OCI ランタイムに修正版 `sysbox-runc` を指定します。
`sysbox-fs` の環境変数 `SYSBOX_PROC_TRANSFER_HELPER` に、信頼する proc helper の実行ファイルの絶対パスを指定します。
未設定の場合は従来の proc mount 処理を使用します。
コンテナの呼び出し元が両 helper の実行ファイルやデーモンの環境変数を書き換えられないように管理します。
ホストの導入設定は本リポジトリの対象外です。

別リポジトリの [sysbox-compat-nix v0.3.0](https://github.com/michibiki-io/sysbox-compat-nix/tree/v0.3.0) は `aarch64-linux` と `x86_64-linux` 向けに正規の Flake 出力 `sysbox-compat` を提供します。
`default`、`sysbox-proc-transfer`、`sysbox-cilium-lab` は同じパッケージの別名です。
NixOS の proc 転送用モジュールはデーモンと proc helper を選択し、ランタイムは別途設定します。
[NixOS の導入手順](https://github.com/michibiki-io/sysbox-compat-nix/blob/v0.3.0/README.md#nixos-で利用する) に従い、パッケージの完全なコミット SHA を固定してください。
デーモンとランタイムには Nix ストア上の依存が必要で、両 helper（`bin/proc-mount-helper` と `bin/sysfs-mount-helper`）は静的リンクです。
パッケージのネイティブ CI はビルドと個別テストを対象とし、実行時の全面的な対応を保証しません。

### sysfs の有効化

Issue #5 は sysfs 用の独立した任意の転送経路を追加します。
信頼するデーモンの環境変数 `SYSBOX_SYSFS_TRANSFER_HELPER` に `sysfs-mount-helper` の絶対パスを指定します。
未設定時の sysfs dispatch と既存 proc helper のソース、FD 契約を維持します。
有効化した状態での登録には参照できる `/sys` マウントと保護情報が必要です。
転送には型が `sysfs`、mountinfo の Root が `/` の `/sys` と、外側 rootfs 内の実ディレクトリ `/tmp` が必要です。
[ファイルシステムの動作条件](docs/compatibility.md#sysfs-の-consumer-gate) を参照してください。

非 leader の sysfs probe と直接起動の lifecycle fixture は [実行手順](tests/runtime/README.md#新規-sysfs-と-network-の検査) を参照してください。
外側のマスクと読み取り専用マウント、元の bwrap proc と `/sys` bind 検査を維持します。
新規 sysfs マウントと FUSE 修正の受け入れ条件は proc 転送の受け入れ条件から独立しています。
運用用 helper は検査用 checkpoint socket を受け付けません。
installer、ホスト daemon、cluster の設定変更は提供しません。

### Cilium 互換機能

Sysbox v0.7.1 の標準ビルドは Cilium の perf 出力と JIT プローブを扱い、`SYSBOX_EXPERIMENT_PERF_OUTPUT` の設定は不要です。
ホストには cgroup v2、委譲する bpffs と BPF token、ジョブ単位の cgroup 登録と後片付けが必要です。
既存の OCI seccomp による拒否が優先され、認可や要求の条件は文書に記載したネイティブ amd64/arm64 の範囲に限ります。
対象外の要求はカーネルの処理に委ねます。
perf の検査は FD とリングの設定を確認し、イベントの配信は測定しません。JIT 応答は定めたスカラー値に限ります。
kind では Cilium の init container が動く前に委譲済みの bpffs と書き込み可能な `/etc/sysctl.d` を用意します。
[標準ビルドとホスト側の前提](docs/cilium-lab.md#標準ビルドとホスト側の前提) を参照してください。

任意の Nix 出力 `cilium-warning-agent` は、TCX の復旧とソケット終了を使い捨て環境で検証するための Cilium v1.20.4 の単体 Agent です。
標準 Sysbox ビルドには含めず、未改変 Agent の利用にも必要ありません。
[警告に対応する試験手順](docs/cilium-lab.md#警告に対応する-cilium-側の試験パッチ) と [Nix パッケージの手順](https://github.com/michibiki-io/sysbox-compat-nix/blob/v0.3.0/README.md#警告対応版-cilium-agent) を参照してください。

### 検証

ローカルの静的検査には Python 3、Bash、Linux ヘッダーを使える C コンパイラーが必要です。

```sh
python3 -m unittest discover -s tests/static -v
```

実行時検証は、構成済みの Sysbox コンテナ内で既存の一般ユーザーとして実行します。
`cc`、`/usr/bin/python3`、bubblewrap は事前に用意します。
スクリプトは依存パッケージを導入しません。
実際のホスト PID/User 名前空間の識別子を、運用者が別途取得して位置引数に渡します。
形式は `readlink` が返す `pid:[number]` と `user:[number]` です。
コンテナ内から取得した値をホスト識別子として使いません。

```sh
bash tests/runtime/verify.sh "$HOST_PID_NAMESPACE" "$HOST_USER_NAMESPACE"
# 同じコンテナ内で任意に実行する負荷検査:
python3 tests/runtime/stress-proc.py
```

検証スクリプトは自身の配置先からの相対パスと、呼び出し元が所有する `mktemp` ディレクトリを使います。
作業ファイルは終了時に削除します。
元の bwrap コマンド、sandbox の PID 名前空間との一致、seccomp、登録済み保護の inode、マスク、読み取り専用属性、取り外しの拒否、再帰的に読み取り専用にした procfs を確認します。
`/sys` の検査対象は、`--ro-bind /sys /sys` で保持した既存のツリーです。
新しい入れ子の sysfs mount の修正を検証するものではありません。
任意の負荷検査では、8 ワーカーによる 500 回の変更なしの bwrap mount と、並行する nsenter/FUSE プロセスの回収を確認します。
検査結果と名前空間の識別子はローカルの診断情報として扱い、実機の生ログを公開しません。

既存の helper 拒否検査は、信頼された起動元の環境で実行します。
運用者が渡すコンテナ内実行コマンドで、この検査専用の sandbox を作成します。
Python 3.12 以降と、名前空間のメタデータにアクセスできる root 権限が必要です。
デーモンの設定や再起動は行いません。
専用テストコンテナを使い、一回の呼び出しで一つの拒否条件を指定します。

```sh
python3 tests/runtime/helper-rejections.py \
  --outer-pid "$OUTER_INIT_PID" --helper "$TRUSTED_HELPER" \
  --uid "$CALLER_UID" --gid "$CALLER_GID" --mode wrong-owner \
  --exec docker exec --user "$CALLER_UID:$CALLER_GID" test-container
```

他の検査モードは `dead-requester`、`unsupported-flags`、`mapped-launcher` です。
`OUTER_INIT_PID` には、起動元の procfs から見た、登録済み外側コンテナの init PID を渡します。
検査は固有の識別子を付けた自身の sandbox だけを探索し、固定した pidfd で終了させます。
終了対象として任意の PID を受け取ることはありません。
helper の mount は引き続き、UID/GID をマッピングした外側の User 名前空間の権限で行います。

runner は TID と TGID が異なる非 leader の mount を、異なる Mount namespace と独立した観測 process で確認し、見える登録済み proc submount をすべて検査します。
終了、通知失効、exec の競合を決定的に検査する手順は [設計](docs/design.md) と [実行コマンド](tests/runtime/README.md) に記載します。
thread pidfd には `PIDFD_THREAD` が必要で、未対応の場合は元の errno で拒否します。
TGID への置き換えや保護のない mount への fallback はありません。

CI は静的検査と、公開されている入力からのネイティブコンテナビルドを実行します。
対応する Sysbox 環境での実行時検証は行いません。
過去の実行時検証は、それぞれのリビジョンに限った証跡です。

- procfs：更新した対で非 leader と lifecycle の検査が 2026-10-14 に、修正した verifier の検査が 2026-10-16 に成功しました。いずれも arm64/Linux 7.1.0/Sysbox 0.7.1/bubblewrap 0.9.0 です。任意の proc 項目が実際に欠けるカーネルは未検証です。
- 新規 sysfs とネットワーク表示用 FUSE：初回 sysfs の対で 2026-10-15 に arm64/Linux 7.1 の補助検査が成功しました。後続の対の検証範囲は異なります。未改変の下流 v0.4.1 suite は新規 sysfs の8件に成功した後、interleave で失敗し、後続の検査は未実行です。移植性のための検査修正は新たな実行時検証の成功を意味しません。**AC7 の実 amd64/6.18.18-talos、Sysbox 0.7.1、bwrap 0.12.0 での検証は talos-sysbox-installer への取り込みまで保留（未実行）です。**
- FUSE overlay：初回候補は amd64/Linux 6.18.64 と arm64/Linux 7.1.0 の両方で、Sysbox 0.7.1 と既定の FUSE アクセス設定を使った入れ子の Docker 27.5.1、`fuse-overlayfs` の検査に成功しました。未改変 BuildKit v0.35.1 の SBOM 検査は両方で失敗し、検査専用パッチを適用した worker では成功しました。実 Talos とリリース規模の性能比較は未実行です。
- Cilium：初期の未改変 v1.20.4 Agent の検査は amd64/Linux 6.18.44 でカタログのネットワーク5件に成功しました。後続の NixOS カタログジョブは以前の Sysbox 構成で13件に成功しましたが、警告固有の検査は含みません。別の警告対応版 Agent は amd64/Linux 6.18.44/Sysbox 0.7.1 で7件に成功しました。標準の対の perf/JIT 検査には [使い捨て環境での比較](docs/cilium-lab.md#使い捨て環境での比較) を使います。

過去の正確なハッシュ、条件、制約は [動作条件](docs/compatibility.md) を参照し、実際に検査したリビジョンごとに PASS/FAIL/UNRUN を記録してください。

### 関連文書

- [設計](docs/design.md)：procfs 転送の流れとデーモン/helper 間の内部契約。
- [安全性の設計](docs/security-model.md)：認証、名前空間の隔離、登録済みの procfs 保護。
- [動作条件](docs/compatibility.md)：検証済みの条件、レビュー修正の検査、残る制約。
- [Cilium 互換性](docs/cilium-lab.md#日本語)
- [実行時の検証手順](tests/runtime/README.md#日本語)

### ライセンス

独自の helper、検証コード、ビルドツール、文書には、ルートディレクトリの [MIT ライセンス](LICENSE) を適用します。
パッチの Sysbox 部分、別途提供する Cilium の警告対応パッチおよび検査専用の BuildKit パッチは Apache-2.0 の派生物です。
固定した FUSE library の変更部分は [BSD の表示](LICENSES/bazil-fuse.txt) を保持します。
upstream の帰属表示とライセンスは [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) と [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) に保持しています。
静的リンクしたバイナリを再配布する場合は、適用される LGPL の義務を含め、第三者のライセンスを別途確認する必要があります。
ルートディレクトリの MIT ライセンスは、リンクされるすべての依存物を対象にするものではありません。
