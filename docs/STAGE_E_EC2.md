# Stage E on AWS EC2 (mtabe19/qedos fork)

QEDOS を AWS EC2 (Nitro, x86_64) 上で直接起動するための記録。
上流の `docs/X86_BAREMETAL_PLAN.md` (物理 AMD64 マシン向けの調査段階の計画) と重なる部分が多く、
ここではターゲットを EC2 に置き換えて進める。fork の運用ルールは `docs/FORK_NOTES.md`。

## 1. 前提

| 項目 | 内容 |
|---|---|
| ターゲット | EC2 t3 系 (Nitro, Intel)。Legacy BIOS 起動。NIC は ENA、ディスクは NVMe |
| 開発機 | Mac (Apple Silicon)。QEMU は TCG。KVM での確認は C8i 系 (nested virtualization) で行う予定 |
| AWS 操作 | Mac の AWS CLI (`aws login --profile qedos`)。ヘルパー用のインスタンスは使わない |
| イメージ | 当面は上流のビルド済みイメージ (`build/sel4/loader.img.gz`, `sel4_32.elf.gz`)。x86_64 の再ビルド手順は未整備 (後述) |

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
- 残りがないかの確認:

```sh
aws ec2 describe-instances --filters Name=tag:project,Values=qedos-stage-e \
  --query 'Reservations[].Instances[].[InstanceId,State.Name]' --output text --profile qedos
aws ec2 describe-images --owners self --filters Name=tag:project,Values=qedos-stage-e \
  --query 'Images[].ImageId' --output text --profile qedos
aws ec2 describe-snapshots --owner-ids self --filters Name=tag:project,Values=qedos-stage-e \
  --query 'Snapshots[].SnapshotId' --output text --profile qedos
```

## 3. 結果

| Step | 内容 | 結果 (2026-10-20) |
|---|---|---|
| M1-0 | 上流のビルド済みイメージで `tests/test_sel4.py` (macOS, QEMU 11.1.2 TCG) | SEL4_001..006 PASS |
| M1-1 | GRUB ディスクイメージから起動 (SeaBIOS, multiboot2) | SEL4_001..006 PASS |
| M1-2 | EC2 t3.medium で起動 (Legacy BIOS, EBS) | GRUB -> seL4 -> CapDL -> Microkit monitor まで起動。timer_driver と ethernet_driver で停止 (下記) |

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

## 5. 課題と次の手順

1. **EC2 の構成を調べる**: Amazon Linux を user-data で起動し、`lspci -nn` (ENA の BAR・MSI-X)、`/proc/iomem`、
   ACPI テーブル一覧 (HPET の有無)、`dmesg` のクロック関連 (TSC, kvm-clock, HPET) をシリアルに出して回収する
2. **タイマー**: HPET が無い場合は TSC + Local APIC タイマー等の sDDF タイマードライバが必要
3. **x86_64 の再ビルド**: `build-sel4.sh` は `build/echo/` のビルド済み sDDF をコピーするが、リポジトリに無い。
   `scripts/build-sddf.sh` (aarch64 用) を x86_64_generic に対応させる
4. **アドレスのプロファイル化**: `sel4/meta_proofgate.py` の QEMU 前提の値 (virtio BAR `0xFE000000`, DMA `0x7A000000`,
   IOAPIC pin 11, COM1 `0x3F8`, PCI 0:2.0) をマシン別プロファイルへ
5. **ENA ドライバ (sDDF)**: 最大の作業。参考実装のライセンスは取り込み前に確認する
6. **IOMMU**: EC2 では使えない前提で、NIC を信頼境界に含めることを評価記録に明記する
7. **UEFI 版ディスクイメージ**: UEFI のみのインスタンスタイプ向け。上流計画にある GRUB + UEFI の問題を QEMU (OVMF) で先に確認する
