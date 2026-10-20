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
- sDDF への変更は `patches/sddf/*.patch` に置き、`build-sddf.sh` が checkout のたびに当て直す。`build-sel4.sh` は毎回 `build-sddf.sh` を呼ぶ (make が差分だけビルドする)
- `QEDOS_HPET_IOAPIC_PIN` (既定 23): HPET タイマーの IRQ の IOAPIC pin。ドライバ (`-DHPET_IOAPIC_PIN`) と `meta_proofgate.py --hpet-ioapic-pin` の両方に同じ値が渡る。EC2 のタイマー 0 は pin 16-23 にしか出せない (4.1)。QEMU (q35) でも 23 で動く
- `QEDOS_HPET_FORCE_32BIT=1`: 試験用。64 ビットの HPET でも 32 ビットモード + IOAPIC 直接経路で動かし (EC2 と同じ条件)、カウンタを一周の 5 秒前から始める。出力は `build/echo-x86_64_generic-hpet32/`, `build/sel4-x86_64_generic-hpet32/`

EC2 で起動試験 (Mac で):

```sh
scp mtabe@<vm>:qedos/build/disk/qedos-bios-rebuilt.img build/disk/
QEDOS_DISK_IMG=build/disk/qedos-bios-rebuilt.img tools/ec2/boot-test.sh
```

- `QEDOS_CONSOLE_UNTIL='<正規表現>'`: コンソールが一致したら 300 秒を待たずに片付けへ進む
  (例 `'DHCP lease|ENA\|ERROR|Failed assertion'`)。M5-2 では running から約 35 秒で一致し、1 回の試験が約 1 分で終わった

### 2.6 EC2 用イメージ (`QEDOS_PROFILE=ec2-t3`, ENA)

マシン別プロファイル (`sel4/meta_proofgate.py --profile`): `qemu` (既定、virtio-net 00:02.0) と `ec2-t3`
(ENA 00:05.0、`sel4/drivers/ena/`)。sDDF の受信振り分けは宛先 MAC をビルド時に固定するため、ec2-t3 では
固定の ENI を 1 つ作り、その MAC でビルドし、試験のたびにその ENI を付けて起動する。

ENI の作成 (初回のみ、Mac で。ID と MAC は `build/ec2/eni.env` に置き、commit しない):

```sh
aws ec2 create-network-interface --subnet-id <boot-test.sh と同じサブネット> --description qedos-stage-e \
  --tag-specifications 'ResourceType=network-interface,Tags=[{Key=Name,Value=qedos-stage-e-eni},{Key=project,Value=qedos-stage-e}]' \
  --query 'NetworkInterface.[NetworkInterfaceId,MacAddress,PrivateIpAddress]' --output text --profile qedos
# build/ec2/eni.env:
#   QEDOS_EC2_ENI=eni-...
#   QEDOS_NET_MAC=xx:xx:xx:xx:xx:xx
```

ビルド (VM) と起動試験 (Mac):

```sh
QEDOS_PROFILE=ec2-t3 QEDOS_NET_MAC=<MAC> scripts/build-sel4.sh      # 出力 build/sel4-x86_64_generic-ec2-t3/
QEDOS_SEL4_DIR=build/sel4-x86_64_generic-ec2-t3 tools/mk-grub-disk.sh build/disk/qedos-bios-ec2.img
# Mac
set -a; . build/ec2/eni.env; set +a
QEDOS_DISK_IMG=build/disk/qedos-bios-ec2.img tools/ec2/boot-test.sh
```

- `QEDOS_EC2_ENI` を指定すると `--network-interfaces DeviceIndex=0,NetworkInterfaceId=...` で起動する。ENI は片付けで消さない。
  前のインスタンスが終了中で ENI が `in-use` のときは `available` になるまで待つ
- 既存の ENI でも、既定のサブネットの自動割り当てによりパブリック IPv4 が付く (2026-10-20 に確認)。そのまま使う (本人判断)

HTTPS の確認 (M5-4):

```sh
# 初回のみ: 専用のセキュリティグループ (受信は TCP 8443 を自分のグローバル IP /32 からだけ) を作って ENI に付ける。
# ID は build/ec2/eni.env に QEDOS_EC2_SG として置く。グローバル IP が変わったらルールを付け直す
aws ec2 create-security-group --group-name qedos-stage-e-sg --vpc-id <既定の VPC> ...
aws ec2 authorize-security-group-ingress --group-id <SG> --protocol tcp --port 8443 --cidr <自分の IP>/32
aws ec2 modify-network-interface-attribute --network-interface-id <ENI> --groups <SG>

# ターミナル 1
QEDOS_CONSOLE_SECONDS=600 QEDOS_DISK_IMG=build/disk/qedos-bios-ec2.img tools/ec2/boot-test.sh 2>&1 | tee -i /tmp/boot.log
# ターミナル 2 (instance running の 1 分後、DHCP の後)
IP=$(sed -n 's/.*public IPv4: \([0-9.]*\).*/\1/p' /tmp/boot.log); tools/ec2/https-check.sh "$IP"
```

- `tools/ec2/https-check.sh IP [PORT]`: SEL4_001..003 と同じ確認 (TLS 1.3 + X25519MLKEM768 で GET /health -> 200、
  TLS 1.2 と従来の鍵交換は拒否)。VM の QEMU に対しても `tools/ec2/https-check.sh 127.0.0.1 18443` で使える
- `boot-test.sh` は running になったときにパブリック IPv4 を表示する。終わったら Ctrl-C で止めてよい (片付けは行われる)。
  `tee` には `-i` を付ける。付けないと Ctrl-C で tee が先に終わり、片付けの出力がログに残らない
  (以前は片付けの最初の出力で SIGPIPE になりインスタンスが残っていた。今は `on_exit` が SIGPIPE を無視して最後まで片付ける。
  2026-10-20 の M5-5 で、Ctrl-C の後に片付けが最後まで行われ、その出力もログに残ることを EC2 で確認)

### 2.7 backend への転送 (M5-5)

転送先は署名済みの設定 (`proxy.sconf`) の backend 表だけで決まる (LAW_004、`connector_pd.c`)。
`config/sel4/proxy.conf` の backend は QEMU 用の `10.0.2.2` なので、EC2 では backend 用のインスタンスを
QEDOS と同じサブネットに置き、そのプライベート IPv4 を入れた設定を署名して焼き込む。

- 雛形 `config/ec2-t3/proxy.conf.in` (route は `config/sel4/proxy.conf` と同じ)。IP を入れたものと署名済みのものは
  `build/ec2/` に置き、commit しない
- 署名鍵は上流の開発用の鍵 (`config/keys/`、公開済み) のまま。実際のサービスを載せるときは自分の鍵を作り、
  `crates/pg-config/src/lib.rs` の `PUBLIC_KEY` を差し替える
- backend は `tools/ec2/backend.sh up|down`。Amazon Linux 2023 (t3.micro) で `tests/backend.py` を 0.0.0.0 で動かす
  (`QEDOS_BACKEND_BIND`)。鍵ペア・SSH なし。`QEDOS_BACKEND_MINUTES` (既定 120 分) で自分で終了する

初回のみ (Mac で。ID と IP は `build/ec2/eni.env` に足す):

```sh
set -a; . build/ec2/eni.env; set +a
aws ec2 describe-network-interfaces --network-interface-ids "$QEDOS_EC2_ENI" \
  --query 'NetworkInterfaces[0].[SubnetId,VpcId]' --output text --profile qedos   # QEDOS の ENI のサブネットと VPC
aws ec2 create-security-group --group-name qedos-stage-e-backend-sg --description "QEDOS Stage E test backends" \
  --vpc-id <VPC> --query GroupId --output text --profile qedos
aws ec2 authorize-security-group-ingress --group-id <backend SG> \
  --ip-permissions "IpProtocol=tcp,FromPort=19001,ToPort=19002,UserIdGroupPairs=[{GroupId=$QEDOS_EC2_SG}]" --profile qedos
aws ec2 create-network-interface --subnet-id <サブネット> --groups <backend SG> --description qedos-stage-e-backend \
  --tag-specifications 'ResourceType=network-interface,Tags=[{Key=Name,Value=qedos-stage-e-backend-eni},{Key=project,Value=qedos-stage-e}]' \
  --query 'NetworkInterface.[NetworkInterfaceId,PrivateIpAddress]' --output text --profile qedos
# build/ec2/eni.env に追加:
#   QEDOS_BACKEND_SG=sg-...
#   QEDOS_BACKEND_ENI=eni-...
#   QEDOS_BACKEND_IP=172.31.x.x
```

ビルド (VM):

```sh
QEDOS_BACKEND_IP=<backend の IP>
mkdir -p build/ec2
sed "s/@BACKEND_IP@/$QEDOS_BACKEND_IP/" config/ec2-t3/proxy.conf.in > build/ec2/proxy-ec2.conf
scripts/sign-config.sh --sconf build/ec2/proxy-ec2.conf build/ec2/proxy-ec2.sconf
QEDOS_PROFILE=ec2-t3 QEDOS_NET_MAC=<MAC> QEDOS_SIGNED_CONFIG=build/ec2/proxy-ec2.sconf scripts/build-sel4.sh
QEDOS_SEL4_DIR=build/sel4-x86_64_generic-ec2-t3 tools/mk-grub-disk.sh build/disk/qedos-bios-ec2.img
# 確認の手順を QEMU で先に確かめる (既定の設定でビルドした build/sel4-x86_64_generic で QEMU を起動し、tests/backend.py を動かしておく)
tools/ec2/https-check.sh --backend 10.0.2.2 127.0.0.1 18443
```

起動試験 (Mac):

```sh
set -a; . build/ec2/eni.env; set +a
tools/ec2/backend.sh up            # "backends up at ..." が出るまで待つ
# ターミナル 1
QEDOS_CONSOLE_SECONDS=600 QEDOS_DISK_IMG=build/disk/qedos-bios-ec2.img tools/ec2/boot-test.sh 2>&1 | tee -i /tmp/boot.log
# ターミナル 2 (DHCP の後)
IP=$(sed -n 's/.*public IPv4: \([0-9.]*\).*/\1/p' /tmp/boot.log); tools/ec2/https-check.sh --backend "$QEDOS_BACKEND_IP" "$IP"
# 終わったら
tools/ec2/backend.sh down
```

- `https-check.sh --backend` は 1〜3 に加えて SEL4_004 と同じ転送の確認 (4a/4b) と、SEL4_005 と同じ拒否の確認 (5.1〜5.5、
  ステータスコードのみ) を行う。backend 側に漏れていないかの件数は、backend に外から届かないので確認しない

## 3. 結果

| Step | 内容 | 結果 (2026-10-20) |
|---|---|---|
| M1-0 | 上流のビルド済みイメージで `tests/test_sel4.py` (macOS, QEMU 11.1.2 TCG) | SEL4_001..006 PASS |
| M1-1 | GRUB ディスクイメージから起動 (SeaBIOS, multiboot2) | SEL4_001..006 PASS |
| M1-2 | EC2 t3.medium で起動 (Legacy BIOS, EBS) | GRUB -> seL4 -> CapDL -> Microkit monitor まで起動。timer_driver と ethernet_driver で停止 (下記) |
| M2-1 | Ubuntu 24.04 VM (clang/lld 18.1.3, Rust 1.99.1) で x86_64 を再ビルド (2.5) | sDDF echo_server、seL4 用 OpenSSL、`build-sel4.sh` とも成功 (pancake の `cake` は不要) |
| M2-2 | 再ビルドしたイメージで `tests/test_sel4.py` (VM, QEMU 8.2.2 TCG)。`-kernel/-initrd` と GRUB ディスクの両方 | SEL4_001..006 PASS (両方) |
| M2-3 | 再ビルドしたディスクイメージで EC2 t3.medium | M1-2 と同じ (4.1 の 2 か所で停止、tls/http/policy/connector は初期化成功) |
| M3-1 | sDDF `tsc_hpet` を 32 ビット HPET に対応 (`patches/sddf/0001-tsc_hpet-32bit-counter.patch`) | カウンタをソフトウェアで 64 ビットに拡張、一周の半分ごとに必ず割り込みを予約。HPET の値を起動時に表示 |
| M3-2 | QEMU (VM) で通常ビルドと `QEDOS_HPET_FORCE_32BIT=1` | 両方 SEL4_001..006 PASS。強制モードは一周 (`wrapped (1)`) をまたいで PASS |
| M3-3 | EC2 t3.medium (1 回目) | `LEG_RT_CAP` の assert で停止 (レガシー経路なし) |
| M3-4 | EC2 t3.medium (2 回目、IOAPIC pin 2 へ直接経路) | `timer0 cannot be routed to I/O APIC pin 2 (route cap 0xff0000)` で停止 |
| M3-5 | EC2 t3.medium (3 回目、IOAPIC pin 23 へ直接経路) | **timer_driver 初期化成功**。tcp_pd が `listening on 0.0.0.0:8443` まで進み、`wrapped (1)..(3)` を観測 (約 68.7 秒ごと)。ethernet_driver は従来どおり停止 |
| M4 | マシン別プロファイル (`--profile qemu｜ec2-t3`、`QEDOS_PROFILE`) | qemu: `proofgate.system` が変更前と同一 (乱数の MAC を除く)、SEL4_001..006 PASS |
| M5-1 (1 回目) | ENA ドライバ (PCI 確認、リセット、管理キュー、GET_FEATURE)、固定 ENI で起動 | BAR0 が `0xfebf4000` (プロファイルの `0xc0400000` と違う) でドライバの確認により停止 |
| M5-1 (2 回目) | BAR0 を `0xfebf4000` に修正 | **成功**。readless 読み出し、リセット、管理キュー (ポーリング) が動作し、MAC が ENI と一致 |
| M5-2 | 送受信キュー各 1 本 (深さ 256、ホストメモリ配置)、1ms ごとのポーリング、ホスト情報と MTU 1500 の設定 | **成功**。`TCP_PD: DHCP lease acquired` (IP は ENI のプライベート IP と一致)。送信 350B x2 / 受信 590B x2 (DHCP)、送信 42B x4 (ARP と推測)、エラー 0 |
| M5-3 | MSI-X (入口 0/1/2 を同じ vector 106 へ、送信 CQ 1・受信 CQ 2)、ポーリングは 100ms の予備のみ | **成功**。DHCP 取得後、割り込み 12 回 / 予備ポーリングで見つかった完了 0。途中で届いた ARP (と推測) にも応答 |
| M5-4 | 手元の Mac からパブリック IPv4 の 8443 へ `tools/ec2/https-check.sh` | **成功**。TLS 1.3 + X25519MLKEM768 + AES-256-GCM で GET /health -> 200 (1 秒未満)、TLS 1.2 と X25519 / P-256 単独は拒否。コンソールにも `TLS_PD: handshake OK ... X25519MLKEM768` と `handshake rejected (LAW_002/LAW_003)` x3。割り込み 55 回 / 予備ポーリング 0。backend への転送は未確認 (転送先が QEMU 用の 10.0.2.2) |
| M5-5 | 同じサブネットの backend (AL2023 t3.micro + `tests/backend.py`、固定 ENI) の IP を入れて署名した設定で、手元の Mac から `tools/ec2/https-check.sh --backend` | **成功**。1〜5.5 がすべて PASS: POST /api/chat は backend A、GET /game/score は backend B に届き、Host は `backend IP:ポート` に固定、X-Forwarded-For は削除。不正なリクエストは 400/404/405。コンソールに `POLICY_PD: Ed25519 signed config verified OK`。ENA からの外向き TCP も動作。試験中のコンソール出力は取れていない (コンソールの更新が遅く、その前に Ctrl-C で止めたため) |

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
| timer_driver | (M3 前) `timer.c:154` `capability & BIT(COUNT_SIZE_CAP)` で assert。M3 のパッチ後は初期化成功 (下記) | 32 ビット HPET のため。解決済み (3 章 M3) |
| ethernet_driver | `sddf/virtio/transport/pci.c:183` `read_pci_general_device_header` で assert | PCI 0:2.0 に virtio が無い (想定どおり。EC2 は ENA) |
| tls/http/policy/connector | 初期化成功 (Ed25519 署名検証 OK) | M3 前の tcp_pd はタイマーと NIC 待ちで出力なし。M3 後は `TCP_PD: listening on 0.0.0.0:8443` |

HPET (M3 のパッチが起動時に表示した値):

| 項目 | 値 |
|---|---|
| 能力レジスタ | `0x00f4240080860701`: 周期 16ns (62.5MHz)、タイマー 8 個、`COUNT_SIZE_CAP`=0 (32 ビット)、`LEG_RT_CAP`=0 (レガシー経路なし) |
| タイマー 0 設定レジスタ | `0x00ff000000008010`: コンパレータ 32 ビット、周期モード可、FSB (MSI) 配送可、IOAPIC への経路は pin 16-23 のみ (`TN_INT_ROUTE_CAP`=0xff0000) |
| TSC | CPUID 0x15/0x16 から周波数が取れない (`Cannot detect or use TSC frequency`)。時刻の読み出しも HPET を使う (遅い) |
| 割り込み | IOAPIC pin 23 (エッジ) で届く。NIC が無い状態で tcp_pd の lwIP の周期タイムアウトが回り続け、一周の検出が続いたことから判断 |

ENA (M5-1 のドライバが表示した値、Legacy BIOS 起動):

| 項目 | 値 |
|---|---|
| PCI | 00:05.0 `1d0f:ec20`、リビジョン 0 (readless 読み出しを使う)。BIOS 直後のコマンドレジスタ `0x103` (バスマスタ無効、ドライバが有効にする) |
| BAR0 | **`0xfebf4000`** (Legacy BIOS / SeaBIOS)。4.2 の `0xc0400000` は UEFI で起動した AL2023 の値 |
| レジスタ | dev_sts `0x1`、caps `0x3028` (DMA 幅 48 ビット、リセットのタイムアウト 2 秒、管理コマンドのタイムアウト指定なし) |
| 版 | device 0.10、controller 0.0.1 (implementation 1) |
| 属性 | MAC は ENI と一致、最大 MTU 9216、supported_features `0x14005986`、capabilities `0x1d` |
| キューの上限 | 送受信それぞれ SQ/CQ 8 本、深さ 1024、送信ヘッダ最大 128、1 パケットの記述子 送信 17 / 受信 28 |
| I/O キュー (M5-2) | 送信 sq 0 / cq 0 (SQ ドアベル BAR0+0x100)、受信 sq 0 / cq 1 (SQ ドアベル BAR0+0x300)。ホスト情報 (HOST_ATTR_CONFIG) と MTU の SET_FEATURE は成功 |
| AENQ | M5-2 の試験中の通知は 0 件 (通知グループを SET_FEATURE AENQ_CONFIG で設定していないためと推測) |
| MSI-X (M5-3) | 能力は PCI `0xb0`、9 entries、表は BAR0+0x2000。CQ の unmask レジスタ 送信 BAR0+0x504 / 受信 BAR0+0x508。アドレス `0xfee00000`、データ `0x9a` (seL4 vector 106 + 0x30) で届いた |

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
| ENA | BAR0 のみ `0xc0400000` 16KB (32 ビット, non-prefetchable、LLQ 用 BAR2 なし。アドレスは UEFI 起動時の値で、Legacy BIOS では `0xfebf4000`、4.1)。**MSI-X のみ** (9 ベクタ、能力は PCI `0xb0`、テーブル BAR0+0x2000、PBA BAR0+0x3000)、INTx 無効 |
| RAM (Linux の e820) | `0x1000-0x9ffff`、`0x100000-0xbbccdfff`、`0xbbfde000-0xbff7bfff`、`0x100000000-0x13b3fffff` |
| IOAPIC / シリアル | IOAPIC `0xfec00000` GSI 0-23。COM1 16550A `0x3f8` IRQ 4 |

## 5. 課題と次の手順

1. ~~EC2 の構成を調べる~~ (済、4.2)
2. ~~**x86_64 の再ビルド**~~ (済、2.5 と 3 章 M2): `build-sddf.sh` を x86_64_generic に対応させ、
   `build-sel4.sh` は x86_64 でも sDDF を自分でビルドして `build/sel4-x86_64_generic/` に出力するようにした
3. ~~**タイマー**~~ (済、3 章 M3): sDDF `tsc_hpet` を 32 ビット HPET と IOAPIC 直接経路に対応させた。
   TSC deadline タイマーは seL4 カーネルがスケジューリングに LAPIC タイマーとして使うため、ユーザーレベルのドライバでは使えない
   (`timer.c` のコメント)。上流 sDDF (2026-10-20 時点の main) に 32 ビット HPET の対応は無い
4. ~~**アドレスのプロファイル化**~~ (済、2.6 と 3 章 M4): `--profile qemu｜ec2-t3`。HPET pin 23 と COM1 は共通、
   ec2-t3 は ENA 00:05.0 / BAR0 `0xfebf4000` / DMA `0x7A000000` (64KB) / 固定 ENI の MAC
5. **ENA ドライバ** (`sel4/drivers/ena/`、Amazon の ena_defs は BSD-3-Clause): 段階的に進める
   - ~~M5-1~~ (済): PCI 確認、リセット、管理キュー (ポーリング)、属性の取得
   - ~~M5-2~~ (済): 送受信のキュー各 1 本 (ホストメモリ配置)、タイマーで 1ms ごとにポーリング。VPC の DHCP からアドレスを取得
   - ~~M5-3~~ (済): MSI-X。Microkit は MSI を 1 つの PCI デバイスにつき 1 つしか持てない (`sdf.rs` の重複チェック) ため、
     ENA の入口 0/1/2 に同じアドレスとデータを書いて 1 つの IRQ で受ける。seL4 は MSI のアドレスとデータを設定しないので
     ドライバが書く (アドレス `0xFEE00000`、データは vector + 0x30。Microkit 2.3.1 の実機で確認)。100ms の予備ポーリングは残す
   - ~~M5-4~~ (済): HTTPS の疎通。専用のセキュリティグループで自分の IP からだけ 8443 を許可し、`https-check.sh` で確認
   - ~~M5-5~~ (済、2.7): backend への転送。同じサブネットの試験用 backend (AL2023 + `tests/backend.py`) と、その IP を入れた署名済み設定
   - 次: 実際のサービスへの転送 (自分の署名鍵)、性能 (TSC の周波数、項目 8)
6. **IOMMU**: EC2 では使えない前提で、NIC を信頼境界に含めることを評価記録に明記する
7. **UEFI 版ディスクイメージ**: UEFI のみのインスタンスタイプ向け。上流計画にある GRUB + UEFI の問題を QEMU (OVMF) で先に確認する
8. **TSC の周波数**: EC2 では CPUID 0x15/0x16 から取れず、時刻の読み出しが HPET になる (性能の問題)。
   CPUID 0x40000010 (ハイパーバイザが周波数を知らせる leaf) を使うか、HPET と比べて測るかを検討する (未調査)
