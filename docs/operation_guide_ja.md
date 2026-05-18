# WScan 実検査運用ガイド

このドキュメントは、WScan を実際の検査業務や検証環境で使う前に確認する運用手順をまとめたものです。画面操作そのものは [dashboard_usage_ja.md](dashboard_usage_ja.md) を参照してください。

## 基本方針

WScan は、クロール、攻撃計画、ペイロード投入、証跡保存、レポート生成を自動化します。実検査では、検査対象の許可範囲、認証状態、除外 URL、リクエスト負荷、証跡の確認方法を先に決めてから実行してください。

推奨する流れは次のとおりです。

```text
事前確認 -> ダッシュボード起動 -> スコープ設定 -> 小さく試行 -> 本検査 -> レポート確認 -> 再検査
```

## 1. 事前確認

検査前に、少なくとも次を確認します。

| 項目 | 確認内容 |
| --- | --- |
| 許可範囲 | 対象ドメイン、サブドメイン、IP、検査可能時間帯 |
| 禁止操作 | ログアウト、削除、購入、送信、パスワード変更、外部通知など |
| 認証方式 | Cookie、ログインフォーム、Authorization ヘッダ、SSO、MFA の有無 |
| 環境 | 本番、ステージング、ローカル、検証用レプリカ |
| 負荷条件 | リクエスト間隔、並列数、上限リクエスト数、WAF/IDS 通知先 |
| 証跡要件 | HTML レポート、JSON、SARIF、再現コマンド、スクリーンショット |

副作用がある操作は、自動検査の対象から除外する前提で進めます。

## 2. ダッシュボード起動

通常は、先にダッシュボードだけを起動します。

```bash
python3 main.py serve --port 8765
```

ブラウザで開きます。

```text
http://localhost:8765
```

この起動方法では、Target URL や認証情報を画面で確認してから検査を開始できます。

## 3. スコープ設計

検査対象には「攻撃してよい URL」と「ログインや画面遷移のためにアクセスしてよいが攻撃しない URL」があります。

| 種別 | 例 | 設定方針 |
| --- | --- | --- |
| 攻撃対象 | `https://app.example.com/` | Target URL / Target URL scope に入れる |
| アクセスのみ | `https://login.example.com/` | Access URL scope に入れる |
| 除外 | `/logout`, `/delete`, `/payment`, `/send` | Exclude URL に入れる |
| 除外パラメータ | `csrf_token`, `__RequestVerificationToken` | Exclude parameter に入れる |

CLI で指定する場合は次のようにします。

```bash
python3 main.py scan https://app.example.com \
  --target-url https://app.example.com \
  --access-url https://login.example.com \
  --exclude-urls-file exclude_urls.txt \
  --exclude csrf_token __RequestVerificationToken
```

`exclude_urls.txt` は 1 行 1 URL または URL プレフィックスで記述します。

```text
https://app.example.com/logout
https://app.example.com/account/delete
https://app.example.com/payment
```

## 4. 認証の渡し方

認証が必要なサイトでは、Cookie、ログインフォーム、カスタムヘッダのいずれかを使います。

### Cookie を直接指定

```bash
python3 main.py scan https://app.example.com \
  --cookie "session=abc123; csrf=token"
```

ブラウザからエクスポートした Cookie JSON を使う場合:

```bash
python3 main.py scan https://app.example.com \
  --cookie-file cookies.json
```

### ログインフォームを使う

```bash
python3 main.py scan https://app.example.com \
  --login-url https://app.example.com/login \
  --auth-user user@example.com \
  --auth-pass 'password'
```

ログイン成功後の URL や画面内文字列を確認したい場合:

```bash
python3 main.py scan https://app.example.com \
  --login-url https://app.example.com/login \
  --auth-user user@example.com \
  --auth-pass 'password' \
  --login-success dashboard
```

### Authorization ヘッダを使う

```bash
python3 main.py scan https://api.example.com \
  -H "Authorization: Bearer eyJ..." \
  -H "X-Tenant: test"
```

ヘッダをファイルで渡す場合:

```bash
python3 main.py scan https://api.example.com --header-file headers.yaml
```

トークンが短時間で切れる場合は、`--header-refresh-cmd` と `--header-refresh-interval` を使って更新できます。

## 5. 検査強度の決め方

最初は小さく実行し、問題がなければ強度を上げます。

| 目的 | 推奨設定 |
| --- | --- |
| 接続確認 | `--fast --depth 1 --max-payloads 3 --delay 0.5` |
| 初回診断 | ダッシュボードの「標準Web診断」 |
| 認証あり | 「認証あり診断」または Cookie / Login URL 設定 |
| SPA | `--spa-crawl` または「精度重視診断」 |
| 負荷抑制 | `--delay 1.0`、`--concurrency 1`、`--max-payloads` を小さく |
| 広範囲検査 | depth、checks、manual crawl、HAR を増やす |

CLI 例:

```bash
python3 main.py scan https://app.example.com \
  --checks xss sqli csrf open_redirect security_headers \
  --depth 2 \
  --max-payloads 8 \
  --delay 0.5 \
  --navigation-retries 2
```

## 6. プロキシ連携

Burp Suite、ZAP、mitmproxy などで通信を確認したい場合:

```bash
python3 main.py scan https://app.example.com \
  --proxy http://127.0.0.1:8080
```

ダッシュボードでは、基本設定の Proxy に同じ URL を入力します。

プロキシを使うと、リクエスト/レスポンスの実態、リダイレクト、認証切れ、WAF ブロックを確認しやすくなります。

## 7. 手動クロールと HAR

通常のクロールだけでは到達できない画面は、手動クロールや HAR を使って補います。

手動巡回を記録:

```bash
python3 main.py manual-crawl https://app.example.com --output manual_seed.json
```

保存した巡回結果を検査に使う:

```bash
python3 main.py scan https://app.example.com --manual-crawl manual_seed.json
```

ブラウザやプロキシから HAR をエクスポートした場合:

```bash
python3 main.py scan https://app.example.com --har app.har
```

## 8. 出力物の確認順

検査完了後、`output/<timestamp>/` に結果が保存されます。

| ファイル | 確認目的 |
| --- | --- |
| `report.html` | まず見る総合レポート |
| `report_executive.html` | 非技術者向けの要約 |
| `report_developer.html` | 開発者向けの修正観点 |
| `evidence.json` | Finding、HTTP 証跡、検証状態の機械可読データ |
| `reproduction.json` | 再現に必要な条件 |
| `reproduce.sh` | 再現用コマンド |
| `remediation_plan.md` | 修正方針 |
| `report.sarif` | CI/CD やコードスキャン連携 |
| `scan_config.json` | 実行時設定の記録 |

運用では、まず `report.html` で全体を見て、重要 Finding は `evidence.json` と `reproduce.sh` で再現性を確認します。

## 9. Finding の確認観点

検出結果は、次の順で確認します。

1. `Severity` が Critical / High のものを優先する。
2. `verified` や `confidence` を確認する。
3. `evidence_type` と `evidence_details` で証拠の種類を見る。
4. Request / Response を見て、実際に攻撃入力が届いているか確認する。
5. 再現コマンドまたは手動手順で再現する。
6. 認証状態やロール差分が必要な Finding は、別セッションで再確認する。

`alert()` 発火、DB エラー、時間差、権限差分、機密情報パターンなど、証拠の種類によって確度が異なります。

## 10. 再検査と差分確認

修正後の再検査では、前回出力ディレクトリを指定します。

```bash
python3 main.py scan https://app.example.com \
  --previous-scan output/20260519_030611
```

レポート上で、新規、修正済み、継続中の Finding を確認できます。修正確認では、前回と同じ認証情報、同じスコープ、同じ主要チェックで比較することが重要です。

## 11. 実検査前の最終チェックリスト

- Target URL が許可範囲内である。
- ログアウト、削除、送信、決済、パスワード変更 URL を除外した。
- 認証 Cookie またはログイン情報が有効である。
- プロキシや VPN が必要な場合は設定済みである。
- `--delay` と `--concurrency` が対象環境の負荷条件に合っている。
- 初回は `--fast` や小さい `--max-payloads` で接続確認した。
- レポート保存先と証跡の扱いを決めた。
- 検査中に問題が出た場合の停止判断と連絡先を決めた。
