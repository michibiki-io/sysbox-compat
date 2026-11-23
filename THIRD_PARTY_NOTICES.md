# Third-party notices / 第三者の帰属表示

## Contents / 目次

- [English](#english)
- [日本語](#日本語)

## English

`patches/proc-transfer.patch`, `patches/sysfs-transfer.patch` and `patches/fuse-overlay-mount.patch` modify Sysbox v0.7.1 `sysbox-fs` and the `sysbox-runc` namespace-entry source linked into it. The Sysbox changes are Apache-2.0 derivatives. The sysfs patch also modifies the pinned nestybox/fuse `bazil/fs/serve.go`; that portion retains its BSD terms and Tommi Virtanen / Go Authors copyright notices in [LICENSES/bazil-fuse.txt](LICENSES/bazil-fuse.txt). The patch is a prominent record of modifications; applying it retains existing upstream file copyright/license headers. The upstream Sysbox license, including **Copyright 2020 Nestybox, Inc.**, is reproduced unchanged in `LICENSES/Apache-2.0.txt`. Public source repositories and immutable component revisions are recorded in `build/sources.lock.json`.

The independently authored C helper, portable validation programs, packaging scripts and documentation use the root MIT license, Copyright (c) 2026 michibiki.io. This does not relicense upstream Sysbox, its dependencies or generated protobuf code.

No prebuilt binaries are distributed in this issue. A packager redistributing the statically linked outputs must identify the dependencies actually linked, retain applicable licenses/copyright/NOTICE material, provide corresponding source or relinking materials where required (including applicable LGPL obligations), and satisfy each dependency's redistribution conditions. Root MIT is not a binary license inventory or a substitute for those obligations. The builder's package inputs and Go dependencies must be reviewed for the actual build; this source package does not fabricate a complete binary dependency inventory.

The test fixture `tests/runtime/buildkit-fuse-bind.patch` modifies the Apache-2.0 licensed
[BuildKit v0.35.1 source](https://github.com/moby/buildkit/tree/v0.35.1).
It serves the isolated SBOM probe.

The experimental `patches/cilium-v1.20.4-warning-lab.patch` modifies
[Cilium v1.20.4](https://github.com/cilium/cilium/tree/beb276d2f38d4aadfda14710acf8d14a0f1ba723).
Affected source files retain their Apache-2.0 headers and copyright attributed
to the Authors of Cilium. The patch records the modifications. [Upstream license](https://github.com/cilium/cilium/blob/beb276d2f38d4aadfda14710acf8d14a0f1ba723/LICENSE)

## 日本語

`patches/proc-transfer.patch`、`patches/sysfs-transfer.patch`、`patches/fuse-overlay-mount.patch` は Sysbox v0.7.1 の `sysbox-fs` と、そこにリンクする `sysbox-runc` namespace-entry source を変更する Apache-2.0 の派生物です。
sysfs patch は固定した nestybox/fuse の `bazil/fs/serve.go` も変更します。
この部分の BSD 条項と Tommi Virtanen / Go Authors の著作権表示は [LICENSES/bazil-fuse.txt](LICENSES/bazil-fuse.txt) に保持します。
patch が変更箇所を明示し、適用時には upstream file の copyright/license header を保持します。
**Copyright 2020 Nestybox, Inc.** を含む upstream Sysbox license は、`LICENSES/Apache-2.0.txt` に変更せず収録しています。
公開 source repository と固定 component revision は `build/sources.lock.json` に記録しています。

独自の C helper、移植可能な検証プログラム、packaging script、文書には root の MIT license（Copyright (c) 2026 michibiki.io）を適用します。
upstream Sysbox、その依存物、生成 protobuf code の license を変更しません。

この Issue では事前ビルド済み binary を配布しません。
static linked output を再配布する packager は、実際にリンクした依存物を特定し、適用される license、copyright、NOTICE を保持する必要があります。
適用される LGPL の義務を含め、必要な対応 source や relink 用資料を用意し、各依存物の再配布条件を満たしてください。
root の MIT は binary license inventory でも、これらの義務の代替でもありません。
実際のビルドで builder package と Go dependency を確認する必要があります。
この source package は完全な binary dependency inventory を作成したとは主張しません。


SBOM 検証用の `tests/runtime/buildkit-fuse-bind.patch` は、Apache-2.0 の
[BuildKit v0.35.1 ソース](https://github.com/moby/buildkit/tree/v0.35.1) に対するパッチです。

試験用の `patches/cilium-v1.20.4-warning-lab.patch` は
[Cilium v1.20.4](https://github.com/cilium/cilium/tree/beb276d2f38d4aadfda14710acf8d14a0f1ba723)
を変更します。パッチ適用後も対象ファイルの Apache-2.0 と Authors of Cilium の
著作権表示を保持します。 [上流のライセンス](https://github.com/cilium/cilium/blob/beb276d2f38d4aadfda14710acf8d14a0f1ba723/LICENSE)
