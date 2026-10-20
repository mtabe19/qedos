# Fork 運用メモ (mtabe19/qedos)

このリポジトリは shi3z/qedos の非公式 fork。上流とは無関係に、AWS EC2 での実機ブート (Stage E) を試す。
上流への PR は将来検討するが、現時点では予定しない。

## リモートとブランチ

| 名前 | URL | 用途 |
|---|---|---|
| origin | https://github.com/mtabe19/qedos.git | 自分の fork。push はここだけ |
| upstream | https://github.com/shi3z/qedos.git | 上流。fetch のみ。push URL は `DISABLE` にしてある |

- `main`: 上流に追従するだけ。直接コミットしない
- `stage-e-ec2`: 作業ブランチ

上流の取り込み:

    git fetch upstream
    git switch main && git merge --ff-only upstream/main && git push origin main
    git switch stage-e-ec2 && git merge main

GitHub の「Sync fork」ボタンでも main は更新できる。

## 注意点

1. **公開リポジトリである**: 本番用の証明書・秘密鍵・署名鍵、AWS のアカウント ID・インスタンス ID・EIP などはコミットしない。
   `config/dev`・`config/keys` は上流が開発用として公開しているもので問題ない
2. **PR の送り先**: fork で PR を作ると base が既定で上流 (shi3z/qedos) になることがある。自分用の PR は base を `mtabe19/qedos` にする。
   push 直後に出る黄色いバナー「had recent pushes / Compare & pull request」は本人にだけ表示される
   (ログアウト状態で確認、2026-10-20)。`Compare & pull request` は押さない
3. **上流への通知**: issue・コメント・PR は作者に通知が飛ぶ。内容がまとまるまで送らない
4. **脆弱性を見つけたら**: 上流の Security policy に従い、公開 issue ではなく非公開で報告する
5. **公式と誤解されないようにする**: README 先頭の非公式 fork の注記は必要になったら入れる

## ライセンス

- `Cargo.toml` の workspace に `license = "Apache-2.0"`。リポジトリ直下に LICENSE ファイルはない (2026-10-20 確認)。
  Rust 以外 (`sel4/` の C、スクリプト) も同じかは未確認
- Apache-2.0 で守ること: 変更したファイルには変更した旨を残す、元の著作権表示を消さない
- `third_party/` (OpenSSL、seL4、sDDF、Microkit など) はそれぞれのライセンスに従う
- 参考にする外部コード (ENA ドライバの FreeBSD 版など) は、取り込む前にライセンスを確認する
- イメージの配布など公開範囲を広げるときは、作者にライセンスの範囲を確認する

## 関連

- Stage E (EC2) の記録: `docs/STAGE_E_EC2.md`
- 上流の bare-metal 計画: `docs/X86_BAREMETAL_PLAN.md`
