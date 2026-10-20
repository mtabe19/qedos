# Stage E on AWS EC2 (mtabe19/qedos fork)

QEDOS を AWS EC2 (Nitro, x86_64) 上で直接起動するための記録。
上流の `docs/X86_BAREMETAL_PLAN.md` (物理 AMD64 マシン向けの調査段階の計画) と重なる部分が多く、
ここではターゲットを EC2 に置き換えて進める。fork の運用ルールは `docs/FORK_NOTES.md`。

## 1. 前提

| 項目 | 内容 |
|---|---|
| ターゲット | EC2 t3 系 (Nitro, Intel)。Legacy BIOS 起動。NIC は ENA、ディスクは NVMe |
| 開発機 | Mac (Apple Silicon): ソースの編集、EC2 の操作、QEMU (TCG) での確認。x86_64 のビルドは Intel Mac の VMware 上の Ubuntu 24.04 VM (2.5)。KVM での確認は未実施 (VM 内で `/dev/kvm` は使える) |
| AWS 操作 | Mac の AWS CLI (`aws login --profile qedos`)。ヘルパー用のインスタンスは使わない |
| イメージ | 上流のビルド済みイメージ (`build/sel4/loader.img.gz`, `sel4_32.elf.gz`)、または VM で再ビルドしたもの (`build/sel4-x86_64_generic/`, 2.5) |

## 2. 手順

### 2.1 Mac の準備

```sh
brew install qemu openssl@3 rust i686-elf-grub xorriso mtools
cargo install --locked coldsnap          # ~/.cargo/bin/coldsnap
aws login --profile qedos                # AWS CLI 2.32.0 以上
```

### 2.2 QEMU での確認

```sh
python3 tests/test_sel4.py                       # 上流と同じ (-kernel/-initrd)
tools/mk-grub-disk.sh                            # build/disk/qedos-bios.img (MBR + GRUB i386-pc + FAT32)
QEDOS_BOOT=disk python3 tests/test_sel4.py       # SeaBIOS -> GRUB -> seL4
```

### 2.3 EC2 での起動試験

```sh
tools/ec2/boot-test.sh            # snapshot -> AMI -> t3.medium -> console log -> 後片付け
tools/ec2/boot-test.sh --keep     # 残す。後で --cleanup build/ec2/run-<日時>.env
```

- ディスクイメージは coldsnap で EBS スナップショットに直接アップロードする (EBS direct API)
- AMI は `--boot-mode legacy-bios --ena-support` で登録する (Nitro のタイプは ENA フラグ付きの AMI が必要。OS 側の ENA ドライバの有無とは別)
- インスタンスはパブリック IP なし、キーペアなし、デフォルト SG。リソースには `project=qedos-stage-e` タグを付ける
- コンソールは `ec2 get-console-output --latest` で約 1 分ごとに取得し `build/ec2/console-<日時>.log` に保存する
  (アカウントのシリアルコンソールアクセス設定は無効のままで取得できた)
- 残りがないかの確認 (インスタンスは終了を待たずに後片付けするので、数分後に `terminated` を確認する):

```sh
aws ec2 describe-instances --filters Name=tag:project,Values=qedos-stage-e \
  --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text --profile qedos
aws ec2 describe-images --owners self --filters Name=tag:project,Values=qedos-stage-e \
  --query 'Images[].ImageId' --output text --profile qedos
aws ec2 describe-snapshots --owner-ids self --filters Name=tag:project,Values=qedos-stage-e \
  --query 'Snapshots[].SnapshotId' --output text --profile qedos
```

### 2.4 EC2 の構成調査

```sh
tools/ec2/collect-facts.sh        # Amazon Linux 2023 を user-data 付きで起動し、調査結果をシリアルから回収
```

- 結果は `build/ec2/facts-<type>-<日時>.txt` (内部 IP などを含むので commit しない)
- user-data は標準出力に出す (cloud-init -> journal -> シリアル)。`/dev/ttyS0` に直接書くと getty とぶつかって止まった
- 調査後 180 秒待ってから停止する (`get-console-output --latest` の更新が約 1 分ごとのため)。OS からの停止は stop、最後にスクリプトが削除する
- `QEDOS_EC2_TYPE` で他のインスタンスタイプも調べられる

### 2.5 x86_64 の再ビルド (Ubuntu VM)

上流のビルド手順は Linux x86_64 前提のため、Intel Mac の VMware Fusion 上の Ubuntu 24.04 VM でビルドする
(4 vCPU / 8GB / ディスク 60GB。インストーラは LVM の約半分しか / に割り当てないので `lvextend -l +100%FREE -r` で広げる)。
接続はすべて Mac から VM に向けて張る (Mac のリモートログインは使わない)。以下 `<vm>` は VM のホスト名。

VM の準備 (初回のみ):

```sh
sudo apt install -y build-essential clang lld llvm make git curl python3-venv perl qemu-system-x86 grub-pc-bin mtools
curl -sSf https://sh.rustup.rs | sh -s -- -y && . ~/.cargo/env && rustup target add x86_64-unknown-none
# Mac から rsync した後、~/qedos で
python3 -m venv third_party/venv && third_party/venv/bin/pip install 'sdfgen==0.35.0'
mkdir -p third_party/microkit && curl -fL https://github.com/seL4/microkit/releases/download/2.3.1/microkit-sdk-2.3.1-linux-x86-64.tar.gz | tar xz -C third_party/microkit
scripts/build-openssl.sh          # ホスト用 OpenSSL 3.6.1 (試験の pg-proxy / openssl s_client 用。distro の 3.0 は ML-KEM 非対応)
```

ソースを送る (Mac の qedos で。`.git`・`third_party/`・`build/` は送らない):

```sh
rsync -av --delete \
  --exclude=/.git/ --exclude=/third_party/ --exclude=/build/ \
  --exclude=/target/ --exclude=/sel4/rust_pds/target/ \
  --exclude=/tools/conda/ --exclude=/tools/qemu/ \
  --exclude=__pycache__/ --exclude=.DS_Store \
  ./ mtabe@<vm>:qedos/
```

ビルドと試験 (VM の ~/qedos で):

```sh
scripts/build-sel4.sh             # seL4 用 OpenSSL と sDDF (build/echo-x86_64_generic) も無ければ作る
QEDOS_SEL4_DIR=build/sel4-x86_64_generic python3 tests/test_sel4.py
QEDOS_SEL4_DIR=build/sel4-x86_64_generic tools/mk-grub-disk.sh build/disk/qedos-bios-rebuilt.img
QEDOS_SEL4_DIR=build/sel4-x86_64_generic QEDOS_DISK_IMG=build/disk/qedos-bios-rebuilt.img QEDOS_BOOT=disk python3 tests/test_sel4.py
```

- 出力は `build/sel4-x86_64_generic/` (上流のビルド済み `build/sel4/` は比較用に残す)。`sel4_32.elf` は SDK のカーネルをコピーする
- 新しい scp はリモート側の `{a,b}` を展開しないので、複数ファイルは rsync で取る

EC2 で起動試験 (Mac で):

```sh
scp mtabe@<vm>:qedos/build/disk/qedos-bios-rebuilt.img build/disk/
QEDOS_DISK_IMG=build/disk/qedos-bios-rebuilt.img tools/ec2/boot-test.sh
```

## 3. 結果

| Step | 内容 | 結果 (2026-10-20) |
|---|---|---|
| M1-0 | 上流のビルド済みイメージで `tests/test_sel4.py` (macOS, QEMU 11.1.2 TCG) | SEL4_001..006 PASS |
| M1-1 | GRUB ディスクイメージから起動 (SeaBIOS, multiboot2) | SEL4_001..006 PASS |
| M1-2 | EC2 t3.medium で起動 (Legacy BIOS, EBS) | GRUB -> seL4 -> CapDL -> Microkit monitor まで起動。timer_driver と ethernet_driver で停止 (下記) |
| M2-1 | Ubuntu 24.04 VM (clang/lld 18.1.3, Rust 1.99.1) で x86_64 を再ビルド (2.5) | sDDF echo_server、seL4 用 OpenSSL、`build-sel4.sh` とも成功 (pancake の `cake` は不要) |
| M2-2 | 再ビルドしたイメージで `tests/test_sel4.py` (VM, QEMU 8.2.2 TCG)。`-kernel/-initrd` と GRUB ディスクの両方 | SEL4_001..006 PASS (両方) |
| M2-3 | 再ビルドしたディスクイメージで EC2 t3.medium | M1-2 と同じ (4.1 の 2 か所で停止、tls/http/policy/connector は初期化成功) |

M2 の上流ビルド済みイメージとの比較:

| 項目 | 結果 |
|---|---|
| `sel4_32.elf` | SDK 2.3.1 のカーネルと上流のビルド済みが同一 (sha256 一致) |
| `proofgate.system` | 同一 |
| `report.txt` | tls_pd の ELF が 2 ページ (8KB) 小さい (5222 -> 5220 frames)。他の PD は同じ。ビルド環境の差によるものと推測 |
| `loader.img` | 77,311,644 -> 77,303,180 バイト |

M1-2 の実行メモ:

| 項目 | 1 回目 | 2 回目 |
|---|---|---|
| アップロード | 約 64 秒、`dispatch failure` の再送 103 回 (全て回復) | `--omit-zero-blocks` で約 17 秒、再送 0 回 |
| 起動ログ | 下記 4 章 | 1 回目と同じ (再現性あり) |
| インスタンスの終了 | 約 4.5 分 | 約 4.3 分。終了前の `stop-instances --force` は効果がなかったので外した |

終了に時間がかかるのは、QEDOS が ACPI のシャットダウンに応答せず、EC2 が強制終了まで待つためと推測。
そのため `boot-test.sh` は終了を要求したら待たずに AMI とスナップショットを片付ける (待つ場合は `QEDOS_WAIT_TERMINATE=1`)。
数分後に 2.3 の確認コマンドでインスタンスが `terminated` になっていることを確認する。

## 4. EC2 t3.medium で観測した事実

### 4.1 QEDOS の起動ログから

| 項目 | 観測 | 備考 |
|---|---|---|
| ブート | BIOS -> GRUB (EBS/NVMe) -> multiboot2 で seL4 | VGA テキストのフレームバッファ情報も渡る |
| メモリ | `0x100000-0xbffe9000` と `0x100000000-0x13c400000` が RAM | QEMU 前提の DMA リング `0x7A000000` は RAM 内に入る (t3.micro 1GiB では入らない) |
| ACPI | RSDT/FADT/MADT あり。IOAPIC `0xfec00000`、LAPIC `0xfee00000` | |
| CPU | APIC 2 個を検出、1 個のみ使用 (`only support 1`) | seL4 の設定がシングルコア |
| IOMMU | `ACPI: 0 IOMMUs detected` | NIC の DMA から tls_pd の鍵を守れない (上流計画の Security issue と同じ) |
| timer_driver | `sddf/drivers/timer/tsc_hpet/timer.c:154` `capability & BIT(COUNT_SIZE_CAP)` で assert | HPET が無い、または別アドレスと推測。要調査 |
| ethernet_driver | `sddf/virtio/transport/pci.c:183` `read_pci_general_device_header` で assert | PCI 0:2.0 に virtio が無い (想定どおり。EC2 は ENA) |
| tls/http/policy/connector | 初期化成功 (Ed25519 署名検証 OK) | tcp_pd はタイマーと NIC 待ちで出力なし |

### 4.2 Amazon Linux 2023 での調査から (`collect-facts.sh`, 2026-10-20)

| 項目 | 観測 |
|---|---|
| CPU | Intel Xeon Platinum 8175M 2.5GHz、2 vCPU。`constant_tsc nonstop_tsc tsc_known_freq tsc_deadline_timer x2apic rdrand fsgsbase pdpe1gb xsave` あり |
| クロック | Linux は tsc を使用 (他に kvm-clock, hpet, acpi_pm)。Nitro は KVM 系 |
| HPET | あり。MMIO `0xfed00000`、8 コンパレータ、**32 ビット**カウンタ 62.5MHz。sDDF `tsc_hpet` の assert は 64 ビット前提が原因 |
| ACPI テーブル | APIC, BGRT, DSDT, FACP, FACS, HPET, SLIT, SRAT, SSDT, WAET。**DMAR なし (IOMMU なし)** |
| チップセット | **i440FX + PIIX3/PIIX4** (QEMU の q35 とは別)。PCI 設定空間は conf1 (`0xcf8`) |
| PCI | 00:03.0 VGA (1d0f:1111)、00:04.0 NVMe EBS (1d0f:8061)、00:05.0 **ENA (1d0f:ec20)** |
| PCI MMIO 窓 | `0xc0000000-0xfebfffff` (64 ビット側は `0x140000000-`) |
| ENA | BAR0 のみ `0xc0400000` 16KB (32 ビット, non-prefetchable、LLQ 用 BAR2 なし)。**MSI-X のみ** (9 ベクタ、テーブル BAR0+0x2000、PBA BAR0+0x3000)、INTx 無効 |
| RAM (Linux の e820) | `0x1000-0x9ffff`、`0x100000-0xbbccdfff`、`0xbbfde000-0xbff7bfff`、`0x100000000-0x13b3fffff` |
| IOAPIC / シリアル | IOAPIC `0xfec00000` GSI 0-23。COM1 16550A `0x3f8` IRQ 4 |

## 5. 課題と次の手順

1. ~~EC2 の構成を調べる~~ (済、4.2)
2. ~~**x86_64 の再ビルド**~~ (済、2.5 と 3 章 M2): `build-sddf.sh` を x86_64_generic に対応させ、
   `build-sel4.sh` は x86_64 でも sDDF を自分でビルドして `build/sel4-x86_64_generic/` に出力するようにした
3. **タイマー**: (a) sDDF `tsc_hpet` を 32 ビット HPET (62.5MHz、約 68.7 秒で一周) に対応させる、または
   (b) TSC (不変・周波数既知) + TSC deadline タイマーを使う。上流 sDDF の新しい版で対応済みかも確認する
4. **アドレスのプロファイル化**: `sel4/meta_proofgate.py` の QEMU 前提の値 (virtio BAR `0xFE000000`, DMA `0x7A000000`,
   IOAPIC pin 11, COM1 `0x3F8`, PCI 0:2.0) をマシン別プロファイルへ。EC2 t3 の値は 4.2 から作る
5. **ENA ドライバ (sDDF)**: 最大の作業。BAR0 のみ・MSI-X 必須。seL4/Microkit (sdfgen `IrqMsi`) で MSI を受け、
   MSI-X テーブルを誰が設定するかを先に確認する。参考実装のライセンスは取り込み前に確認する
6. **IOMMU**: EC2 では使えない前提で、NIC を信頼境界に含めることを評価記録に明記する
7. **UEFI 版ディスクイメージ**: UEFI のみのインスタンスタイプ向け。上流計画にある GRUB + UEFI の問題を QEMU (OVMF) で先に確認する
