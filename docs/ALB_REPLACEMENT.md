# ALB の代わりにする検討 (mtabe19/qedos fork)

作成: 2026-10-20 (検討段階。実装は未着手)
関連: [`STAGE_E_EC2.md`](STAGE_E_EC2.md) (EC2 での起動と M1〜M5)、[`LAWS.md`](LAWS.md) (上流のセキュリティの約束)

この文書には、fork の作者の環境に固有の値 (ホスト名、IP、ALB のルール番号) は書かない。
それらは非公開の try-on-premises 側の文書 (`docs/shared/alb-and-target-groups.md`、relay と garage-nas の `service-info.md`) を参照する。

## 1. 目的

- 今使っている AWS ALB (TLS 終端、ホスト名とパスでの振り分け) の代わりになる仕組みを作る
- ロードバランサーの機能 (複数台への振り分け、ヘルスチェック) は要らない
- 要るのは、ルーティングの設定と、いろいろなサービス (Cookie を使う Web アプリ、大きな応答、アップロード) を通すこと
- 上流 (清水さんの qedos) のコンセプトは生かす: `LAWS.md` の約束は削らず、足すときは Law として明記する

## 2. 上流のコンセプト (`LAWS.md` の読み取り)

`LAWS.md` は、守る約束 (LAW_001〜012) ごとに Spec / Evidence / Assumptions / Not proven を書いている。
根拠は PROVEN-BOUNDED (Kani)、VIPER-AUDITED (Microkit の能力モデル + `check-caps.py`)、TESTED (Linux 版と QEMU の seL4) の 3 段階。

全体の姿勢 (この fork での解釈):

1. **固定の表だけで決める**: route (LAW_001) と backend (LAW_004) は Ed25519 で署名した設定 (LAW_011) の表だけ。実行中に変える手段はない (LAW_010)
2. **PD を分けて能力を最小にする**: TLS の鍵は tls_pd だけ (LAW_008)、拒否したリクエストは connector_pd に届く経路がない (LAW_007)、各 PD は必要な共有メモリとチャンネルだけ (LAW_012)
3. **証明できないところは書く**: OpenSSL の C コード、Kani の入力長の上限など

### 2.1 クライアントのヘッダを backend に渡さないことの効果

`LAWS.md` に Law としては書かれていないが、`pg_rust_format_backend_request` (`sel4/rust_pds/src/lib.rs`) はクライアントのヘッダをすべて捨て、
リクエスト行、固定の `Host`、`Connection: close`、`Content-Length` だけを送る (SEL4_004 が Host の固定と X-Forwarded-For の削除を確認)。
一般的な効果 (HTTP プロキシの攻撃の知識からの整理。QEDOS の文書の記述ではない):

1. **リクエストスマグリングを防ぐ**: QEDOS が長さを付け直すので、Content-Length と Transfer-Encoding の食い違いが backend に届かない
2. **信用されがちなヘッダの偽装を防ぐ**: X-Forwarded-For / X-Real-IP / Forwarded (IP 制限やログ)、Host / X-Forwarded-Host / X-Forwarded-Proto (リダイレクトやメールのリンク、キャッシュ汚染)、前段の認証結果を渡すヘッダ
3. **LAW_001 のすり抜けを防ぐ**: X-Original-URL / X-Rewrite-URL / X-HTTP-Method-Override などで、backend が別のパスやメソッドとして処理するのを防ぐ
4. **backend の弱点に届く入力を減らす**: ヘッダ経由の攻撃 (User-Agent 経由の Log4Shell、Shellshock など)

Cookie と Content-Type を通すと変わること:

- Cookie: ログインの状態が backend に届く。CSRF などの対策は backend の責任になる。**1 つのホスト名の下に複数のサービスを載せると、あるサービスの Cookie が別のサービスにも送られる** (サービスごとの許可リストが要る理由)
- Content-Type: backend のどのパーサが動くかをクライアントが選べる。値を絞れば影響は小さい
- 1〜4 のほかのヘッダは引き続き捨てるので、他の効果は残る

## 3. ALB の使い方と QEDOS の今の作り

| ALB で使っている機能 | QEDOS の今の作り | コンセプトとの関係 |
|---|---|---|
| ホスト名による振り分け (約 20 のホスト名、1 ルールに複数のホスト名、ホスト名 + パスの組み合わせあり) | パスとメソッドだけ。route は 16 本 (`crates/pg-config/src/lib.rs` `MAX_ROUTES`)、署名済み設定は 512B (`scripts/build-sel4.sh`) | 合う。署名済みの固定の表を広げる |
| いろいろなサービスを通す (Cookie、大きな応答、アップロード) | ヘッダは全部捨てる。応答 32KB (`PG_MAX_RESP_RAW`)、リクエストの本文 16KB (`PG_MAX_REQ_RAW`) | 合う。許可リストを Law として明記する |
| 接続元の IP を backend に渡す (X-Forwarded-For。IP を記録するサービスがある) | 付けない | 合う。クライアントの値は捨て、QEDOS が自分で作って付ける |
| メンテナンス画面を一時的に挟む | 固定の応答は `/health` だけ | 合う。route の動作に「固定の応答」を足す |
| 同時の利用 (数秒ごとに再読み込みする画面など) | 同時接続 4 本 (`PG_MAX_CONNS`)。backend への転送は全体で 1 本ずつ | 合う。作業量は大きい |
| TLS (ACM の証明書、TLS 1.2 も受ける) | TLS 1.3 + X25519MLKEM768 だけ (LAW_002/003)。証明書は 1 枚をイメージに焼き込み | **ぶつかる** (4 章の 1) |
| 平文の HTTP:80 (2027 年まで受ける必要があるクライアントがある) | 受けない | **ぶつかる** (4 章の 2) |
| Lambda への転送 | 平文の HTTP で backend に送るだけ | **ぶつかる** (4 章の 3) |
| 証明書の更新 | 署名し直したイメージで再起動 (LAW_010) | 4 章の 4 |

## 4. コンセプトとぶつかる点 (未決定)

1. **TLS を耐量子 (X25519MLKEM768) だけにするか**: 主なブラウザは既定で対応 (Chrome/Edge 131+、Firefox 132+ (Android 145+)、Safari 26+。
   [Cloudflare の一覧](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/)、2026-10-20 に参照)。
   古い端末や、アプリが使う TLS ライブラリの対応は未確認
2. **平文の HTTP:80**: QEDOS は TLS が前提
3. **Lambda への転送**: Function URL は HTTPS なので、backend 向けの TLS クライアントが要る
4. **証明書の更新**: Let's Encrypt なら 90 日ごとにイメージを作り直して再起動することになる

## 5. 方針案: 役割を分ける (未決定)

1〜3 を QEDOS の中で解決するとコンセプトを崩すので、役割を分ける案:

- **QEDOS**: ブラウザ向けの HTTPS (耐量子)。ホスト名 + パスのルーティング、ヘッダの許可リスト、ストリーミング、自分で付ける X-Forwarded-For、固定の応答を足し、
  それぞれ Law として明記する。転送先は中継の EC2 (relay2。Tailscale でオンプレのサーバへ)
- **edge1 (Apache の EC2)**: 平文の HTTP:80、Lambda への転送、耐量子に対応していない古いクライアント向けの HTTPS (平文をやめる 2027 年まで)
- サービスごとに DNS (Route 53) でどちらに向けるかを選ぶ

足す機能の候補と Law:

| 機能 | Law (案) | 根拠の付け方 (案) |
|---|---|---|
| ホスト名 + パス + メソッドの route (複数のホスト名、優先度) | LAW_001 の拡張 | pg-policy の Kani と単体試験、SEL4 の試験 |
| 許可したリクエストヘッダだけを転送 | LAW_013 (新規) | 許可していないヘッダが届かないことを試験 (SEL4_004 の拡張) |
| X-Forwarded-For は QEDOS が作る | LAW_013 に含めるか別に立てる | クライアントの値が届かないことを試験 |
| 応答 (と、のちに本文) のストリーミング | LAW_006、LAW_009 | 少しずつ進む検査器の Kani、途中で切れた接続の片付けの試験 |
| 固定の応答 (メンテナンス画面) | LAW_007 の範囲 (転送しない) | 試験 |
| 同時接続と backend への同時転送 | LAW_009、LAW_012 | 能力モデルの更新と負荷試験 |

## 6. 最初の一歩: nas01 の Zabbix をブラウザで使う (M6、PLAN)

対象は Zabbix 7.0.30 (Apache :80、パス `/zabbix/`)。経路は QEDOS (EC2) → relay2 の新しい vhost → Tailscale → nas01。
QEDOS の試験に使う既定の VPC は relay2 と同じなので、relay2 のプライベート IP にそのまま届く (2026-10-20 に確認)。

### 6.1 測った値 (2026-10-20、Tailscale 経由で直接)

| URL | 圧縮なし | gzip |
|---|---|---|
| `index.php` (ログイン画面) | 3,895 B | - |
| `assets/styles/blue-theme.css` | 276,313 B | 42,353 B |
| `js/browsers.js` | 1,427 B | 737 B |

CSS 1 つで 32KB の上限を超える。ログイン後の画面は測っていない (curl でのログインに失敗。Zabbix 7.0 のログインフォームの項目は未確認)。
上限を決め打ちせず、ストリーミングにする (案 2) と決定 (2026-10-20)。

### 6.2 今の応答の経路 (ソースで確認)

| 区間 | 今の作り |
|---|---|
| tcp_pd ← backend | `shm_tcp_conn.rx_buf` に全部ためる。32KB を超えた分は黙って捨てる (`tcp_pd.c` `outbound_recv_cb`)。backend が閉じたら connector_pd に通知 |
| connector_pd | 応答全体を `pg_rust_validate_and_frame_response` で検査し、Content-Length を付け直して `shm_conn_http.raw_resp` に書く |
| http_pd → tls_pd | `shm_tls_http.resp_buf` (リング) に空きを確かめずに書く (`http_pd.c` `send_resp_to_tls`) |
| tls_pd → tcp_pd | リングから読んで暗号化。送信リング (16KB) の空きは確かめるが、暗号化した結果はメモリ上の BIO に上限なくたまる |

ほかに: backend への接続は全体で同時に 1 本 (`shm_tcp_conn` と `shm_policy_conn` が 1 組)。policy_pd へ渡す共有メモリにヘッダを入れる場所がない。
クエリ文字列は `%XX` を通すが、通らない文字もある (`crates/pg-policy/src/lib.rs` `split_target`)。Zabbix の URL が全部通るかは未確認。

### 6.3 PLAN

- **M6-1 経路の確認 (QEDOS は今のまま)**: relay リポジトリに Zabbix 用の vhost (relay2 の空きポート) を足し、nas01 へ中継する。relay2 の SG はそのポートを QEDOS の SG からだけ許可。
  QEDOS の EC2 用設定に `route GET /zabbix/* z` (backend z は relay2)。ログイン画面が返り、CSS が 502 になれば想定どおり
- **M6-2 応答のストリーミング**: 4 区間すべてを空きの分だけ渡すリングにし、空いたら前の PD に通知する (tcp_pd は読まれた分だけ `tcp_recved`、tls_pd は BIO がたまったら `SSL_write` を止める)。
  connector_pd の検査を少しずつ進める形にする (ヘッダ部は今の `parse_response`、本文は Content-Length か `ChunkDecoder`)。クライアントへは長さが分かれば Content-Length、分からなければ chunked。
  QEMU の試験に大きな応答 (Content-Length と chunked) を足し、SEL4_001〜006 も通ることを確認
- **M6-3 リクエストヘッダの許可リスト**: http_pd → policy_pd → connector_pd に許可したヘッダを運ぶ場所を作る。Zabbix には Cookie と Content-Type (推測)。Host、X-Forwarded-*、Connection は引き続き捨てる。LAW_013 を足す
- **M6-4 EC2 で Zabbix を使う**: ブラウザで `https://<QEDOS>:8443/zabbix/` を開き、ログイン、ダッシュボード、グラフまで確認。自己署名の証明書なので警告は出る。QEDOS の SG は自分の IP からだけ
- やらないこと (後回し): backend への同時接続、自分の署名鍵への切り替え

## 7. 決めること

| 項目 | 状態 |
|---|---|
| 大きな応答への対応 | **決定 (2026-10-20)**: ストリーミング (上限の引き上げではない) |
| 許可リストを書く場所 | 未決定。案 a: 署名済みの設定 (サービスごとに変えられる、LAW_011 の署名の対象になる。設定の形式と pg-config の変更が要る)、案 b: コードに固定 (作業が小さい)。どちらも変更にはイメージの作り直しが要る (署名済み設定はビルド時に `policy_pd.elf` に焼き込むため)。複数のサービスを載せるなら Cookie の漏れの点で案 a |
| relay2 に Zabbix 用の vhost と SG のルールを足すか (M6-1) | 未回答 |
| M6-1 から順に進めるか | 未回答 |
| 4 章の 1〜4 と 5 章の役割分担 | 未決定。HTTPS で接続するアプリが耐量子 TLS に対応しているかの確認が要る |

## 8. 未確認・推測

- Zabbix に必要なリクエストヘッダが Cookie と Content-Type で足りるか (推測)
- ログイン後の Zabbix の画面の応答の大きさとリクエストの数 (未計測)
- Zabbix の URL がすべて `split_target` を通るか
- backend への転送が 1 本ずつで、Zabbix の画面の読み込みが実用的な速さになるか
- 古い端末やアプリの TLS ライブラリの X25519MLKEM768 対応
