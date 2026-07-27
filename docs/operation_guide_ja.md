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
| 証明書 | mTLS クライアント証明書、秘密鍵、PFX、社内CA/自己署名CA の有無 |
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

通常ツール層（`scan`）では、Cognito などの Bearer 認証をブラウザ巡回と httpx の全リクエストへ付ける `--bearer` で簡潔に指定できます。Agent モードと Hybrid Phase 1 の Agent 偵察も Bearer/カスタムヘッダに対応しています。

```bash
export WSCAN_BEARER='<token>'
python3 main.py scan https://api.example.com --bearer "$WSCAN_BEARER"
```

環境変数は `WSCAN_BEARER` に対応します（従来のヘッダ指定も利用でき、明示した Authorization を優先）。serve の保護トークン `WSCAN_AUTH_TOKEN` は control-plane 用のため `--bearer` は参照しません（管理トークンの検査対象への漏洩防止）。

Agent CLI では同じトークンとカスタムヘッダを Agent ブラウザへ渡せます。

```bash
python3 main.py agent https://api.example.com \
  --bearer "$WSCAN_BEARER" \
  -H "X-Tenant: test"
```

`agent` は `--header-file` にも対応します。ダッシュボードの Agent/Hybrid は「認証・Cookie」で指定した Bearer/カスタムヘッダを引き継ぎ、Hybrid では Phase 1 偵察と Phase 2 通常スキャンの両方へ同じ実効ヘッダを渡します。Agent/Hybrid Phase 1 では、対応する browser-use 環境なら CDP `Fetch` で全リクエストを傍受し、各リクエスト URL が明示された target/access スコープのオリジンに属する場合だけ認証ヘッダを付与します。このため、第三者オリジンのサブリソースや外部へのリダイレクト／遷移には認証ヘッダを付与しません。

通常ツール層で認証ヘッダをオリジン単位にスコープ制御する場合は、既定で CDP `Fetch` のリクエスト段階を傍受します。応答本文はバッファリングしないため、SSE（`text/event-stream`）などのストリーミング応答を維持したまま、許可オリジンにだけヘッダを付与します。Service Worker 経由の通信を確実に傍受できないため、スコープ制御時は Service Worker を無効化します。

> ⚠️ **WebSocket 認証の制約**: 認証ヘッダのスコープ制御が有効な間、CDP `Fetch` とフォールバック先の Playwright `context.route()` は WebSocket のアップグレード要求へ認証ヘッダを付与しないため、WebSocket ハンドシェイクには認証ヘッダが付きません。`route_web_socket()` もハンドシェイクヘッダを制御できません。WS 認証が必要な対象や `websocket` スキャナを使う場合は、`config/wscan.yaml` の `browser.header_scope_enforce: false` または `WSCAN_HEADER_SCOPE_ENFORCE=0` を指定し、従来のコンテキスト全体適用へ戻してください。無効化時は起動時に1回警告され、第三者サブリソースにも認証ヘッダが送信されます。対象専用かつ最小権限のトークンを使用してください。既定値は `true` です。

> ⚠️ **残存リスク**: Agent 層は対応する browser-use / cdp_use では新 target を停止状態で検知し、`Fetch.enable` 後に再開します。イベント購読 API が利用できない場合は各ステップ開始時の未設定 target 検出を継続しますが、新 target の初回リクエストには間に合わず、追加認証ヘッダなしで送信される可能性があります（フェイルクローズ）。初期 target で `Fetch.enable` 自体ができない場合は、探索を停止せず従来の CDP `Network.setExtraHTTPHeaders` 方式へフォールバックします。この方式ではブラウザターゲットの全リクエストにヘッダが適用されるため、第三者サブリソースや1ステップ内の外部リダイレクト／遷移へ送信される可能性が残ります。通常ツール層（`scan`）は CDP `Fetch` と httpx の直接送信先 URL の双方でオリジンを判定します。通常ツール層の popup は既定で `context.on("page")` による best-effort 傍受となり、ローカル DevTools ポートを開きません。この場合、popup の初回リクエストには認証ヘッダが付かず（フェイルクローズ）、傍受設定後の2本目以降だけ許可オリジンへ付与されます。初回リクエストにも必要な場合は `--popup-header-intercept`、`WSCAN_POPUP_HEADER_INTERCEPT=1`（または `true`）、または `config/wscan.yaml` の `browser.popup_header_intercept: true` で明示 opt-in できます。ただし有効化すると Chromium 終了まで loopback に無認証の DevTools ポートが開き、同一ホストの別プロセスから Cookie・セッションを含むブラウザ全体を操作され得るため、共有ホストやサーバ運用では推奨しません。Service Worker 経由やクロスオリジン iframe（OOPIF）など CDP session の傍受対象外になる経路には認証ヘッダを付与しません（フェイルクローズ）。CDP を利用できない環境では従来の Playwright `route.fetch()` / `route.fulfill()` 方式へ切り替えるため、SSE など終端しないストリーミング応答が途中で切れる可能性があります。さらに route 登録にも失敗した場合だけコンテキスト全体適用へフォールバックします。ただし、既存検査との互換性のため `follow_redirects=True` を使う一部の httpx リクエストは自動追尾を維持しており、許可オリジンへ付けたカスタム認証ヘッダが外部のリダイレクト先へ引き継がれる可能性が残ります。フォールバック環境、外部リダイレクト、外部リソースを多く含む対象では、権限を絞ったトークンの利用を推奨します。動的な `--header-refresh-cmd` は通常ツール層専用です。

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

### ネイティブ TOTP を使う

通常ツール層（`scan`）のログイン補助として、`otpauth://` URI、生 Base32、QR 画像から TOTP を生成できます。URI だけを渡した場合も TOTP 方式へ自動昇格します。

```bash
export WSCAN_MFA_TOTP_URI='otpauth://totp/Example:ops?secret=<base32-secret>&issuer=Example'
python3 main.py scan https://app.example.com \
  --login-url https://app.example.com/login \
  --auth-user ops --auth-pass 'p@ss' \
  --mfa-type totp --mfa-totp-uri "$WSCAN_MFA_TOTP_URI"
```

`--mfa-totp-secret BASE32` または `--mfa-totp-qr code.png` でも指定できます。QR 読み取りには任意依存の opencv（`pip install opencv-python-headless`）が必要です。シークレット、URI、Bearer トークンは保存されないため、毎回 CLI または環境変数で渡してください。

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

検査可能/停止時間帯は CLI の `--allowed-hours` / `--forbidden-hours`、またはダッシュボードの「基本設定」から指定できます。ダッシュボードでは `Mon-Fri 22:00-06:00` のように1行1件で入力し、空欄なら無効です。

## 6. プロキシ連携

Burp Suite、ZAP、mitmproxy などで通信を確認したい場合:

```bash
python3 main.py scan https://app.example.com \
  --proxy http://127.0.0.1:8080
```

ダッシュボードでは、基本設定の Proxy に同じ URL を入力します。

プロキシを使うと、リクエスト/レスポンスの実態、リダイレクト、認証切れ、WAF ブロックを確認しやすくなります。

## 7. 証明書が必要な環境

mTLS が必要な検査対象では、クライアント証明書を指定します。PEM 形式の場合は証明書と秘密鍵をセットで渡します。

```bash
python3 main.py scan https://secure.example.com \
  --tls-client-cert /path/to/client.crt \
  --tls-client-key /path/to/client.key
```

秘密鍵にパスフレーズがある場合:

```bash
python3 main.py scan https://secure.example.com \
  --tls-client-cert /path/to/client.crt \
  --tls-client-key /path/to/client.key \
  --tls-client-cert-password 'password'
```

PFX/PKCS#12 形式は、Playwright ブラウザのアクセスに使えます。

```bash
python3 main.py scan https://secure.example.com \
  --tls-client-pfx /path/to/client.p12 \
  --tls-client-cert-password 'password'
```

社内CAや自己署名証明書を検証したい場合は、CA バンドルと `--tls-verify` を指定します。

```bash
python3 main.py scan https://secure.example.com \
  --tls-client-cert /path/to/client.crt \
  --tls-client-key /path/to/client.key \
  --tls-ca-cert /path/to/ca.pem \
  --tls-verify
```

ダッシュボードでは、基本設定タブの証明書欄に同じパスを入力します。PFX はブラウザアクセス向け、PEM の cert/key は Playwright と httpx の直接リクエストの両方で使われます。

補足: Playwright ブラウザには任意CAバンドルをコンテキスト単位で渡せないため、ブラウザクロールは従来通り HTTPS エラーを許容します。一方、httpx による直接リクエストは `--tls-ca-cert` と `--tls-verify` でサーバ証明書を検証します。

## 8. 手動クロールと HAR

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

## 9. 出力物の確認順

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

## 10. Finding の確認観点

検出結果は、次の順で確認します。

1. `Severity` が Critical / High のものを優先する。
2. `verified` や `confidence` を確認する。
3. `evidence_type` と `evidence_details` で証拠の種類を見る。
4. Request / Response を見て、実際に攻撃入力が届いているか確認する。
5. 再現コマンドまたは手動手順で再現する。
6. 認証状態やロール差分が必要な Finding は、別セッションで再確認する。

`alert()` 発火、DB エラー、時間差、権限差分、機密情報パターンなど、証拠の種類によって確度が異なります。

## 11. 再検査と差分確認

修正後の再検査では、前回出力ディレクトリを指定します。

```bash
python3 main.py scan https://app.example.com \
  --previous-scan output/20260519_030611
```

レポート上で、新規、修正済み、継続中の Finding を確認できます。修正確認では、前回と同じ認証情報、同じスコープ、同じ主要チェックで比較することが重要です。

## 12. 実検査前の最終チェックリスト

- Target URL が許可範囲内である。
- ログアウト、削除、送信、決済、パスワード変更 URL を除外した。
- 認証 Cookie またはログイン情報が有効である。
- mTLS や社内CAが必要な場合は、クライアント証明書、秘密鍵、CA バンドルを指定した。
- プロキシや VPN が必要な場合は設定済みである。
- `--delay` と `--concurrency` が対象環境の負荷条件に合っている。
- 初回は `--fast` や小さい `--max-payloads` で接続確認した。
- レポート保存先と証跡の扱いを決めた。
- 検査中に問題が出た場合の停止判断と連絡先を決めた。
