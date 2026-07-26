# WScan — Web Security Scanner

WScan は、IPA「安全なウェブサイトの作り方」の脆弱性カテゴリを中心に、Playwright による実ブラウザ操作、決定論スキャナ、LLM を組み合わせた Web 脆弱性検査ツールです。用途に応じて、再現性と確証を重視する **通常モード (`scan`)**、LLM の独自解釈と探索力を重視する **Agent モード (`agent`)**、Agent の発見範囲と通常スキャンの確実性を両立する **Hybrid モード（ダッシュボード）**を使い分けます。Hybrid は Agent を URL 偵察だけに使うのではなく、Agent が見つけた脆弱性仮説も最終レポートへラベル付きで併記します。

> WScan は、自分が管理している環境、または明示的な検査許可を得た環境だけに使用してください。

## 目次

1. [概要 — 3モードの使い分け](#1-概要--3モードの使い分け)
2. [主要スクリーンショット](#2-主要スクリーンショット)
3. [クイックスタート](#3-クイックスタート)
4. [インストール](#4-インストール)
5. [ダッシュボード](#5-ダッシュボード)
6. [CLI リファレンス](#6-cli-リファレンス)
7. [設定リファレンス](#7-設定リファレンス)
8. [LLM アーキテクチャ](#8-llm-アーキテクチャ)
9. [Finding の読み方](#9-finding-の読み方)
10. [Hybrid フロー](#10-hybrid-フロー)
11. [長時間スキャン・見逃し防止](#11-長時間スキャン見逃し防止)
12. [出力・連携](#12-出力連携)
13. [認証・MFA・スコープ・TLS](#13-認証mfaスコープtls)
14. [高度機能](#14-高度機能)
15. [トラブルシューティング](#15-トラブルシューティング)
16. [免責・ライセンス](#16-免責ライセンス)

関連ドキュメント:

| ドキュメント | 内容 |
| --- | --- |
| [ダッシュボード利用ガイド](docs/dashboard_usage_ja.md) | 画面操作をスクリーンショット付きで説明 |
| [実検査運用ガイド](docs/operation_guide_ja.md) | 認証、スコープ、検査強度、証跡、再検査 |
| [サーバー導入ガイド](docs/server_deployment_ja.md) | 常駐、イントラネット公開、トークン認証、Docker |
| [高度機能](docs/advanced_features.md) | batch、flow、HAR などの詳細 |
| [OOB メール設定](docs/oob_email_ja.md) | blind XSS/SSRF、メールヘッダ注入の確証 |
| [トラブルシューティング](docs/troubleshooting_ja.md) | アクセス失敗、認証、検出漏れの切り分け |

## 1. 概要 — 3モードの使い分け

| モード | 入口 | 狙い | Finding の扱い | 向いている場面 |
| --- | --- | --- | --- | --- |
| 通常 | `python3 main.py scan URL` またはダッシュボードの「スキャン開始」 | 確実性 | 決定論スキャナが証拠を判定。LLM は主に計画・ペイロード生成・分析を補助 | 定期診断、再検査、CI/CD、根拠を重視する確認 |
| Agent | `python3 main.py agent URL` または「Agent Browser」タブ | 独自性 | LLM がブラウザを自律操作して発見。`source=agent` として未確証を明示 | 複雑な操作、未知の導線、探索的な仮説発見 |
| Hybrid | ダッシュボードの「ハイブリッド」タブ | 確実性と独自性の中間 | Agent Finding と決定論 Finding を出自ラベル付きで併記 | SPA、複雑な認証導線、探索範囲と再現性を両方取りたい場合 |

通常モードでは、LLM が利用できなくても既定・コミュニティ・決定論的変異ペイロードと静的修正テンプレートへフォールバックできます。Agent モードは LLM 自体が操作主体なので、対応プロバイダーと `browser-use` が必要です。

### 対応チェック種別

`wscan.scanners.SCANNERS` に登録されている 36 種類です。

```text
sqli xss dom_xss os ssti path_traversal csrf header_injection mail_header
open_redirect clickjacking session privesc stored_xss cors info_disclosure
host_header security_headers nosql deserialization request_smuggling ssrf
graphql jwt cms xxe ldap file_upload race_condition websocket secret_leak sri
js_static prototype_pollution cache_poisoning mass_assignment
```

Agent モードの CLI で選べる検査種別は `xss sqli ssti os path_traversal ssrf open_redirect csrf header_injection` です。

### IPA 準拠カバレッジ

| IPA 章番号 | 脆弱性 | チェック名 | 主な手法 |
| --- | --- | --- | --- |
| 1.1 | SQL インジェクション | `sqli` | エラー・ブール・時間ベース |
| 1.2 | OS コマンドインジェクション | `os` | 出力パターン・時間ベース |
| 1.3 | ディレクトリトラバーサル | `path_traversal` | ファイル内容パターン |
| 1.4 | セッション管理の不備 | `session` | Cookie 属性確認 |
| 1.5 | 反射型 XSS | `xss` | ダイアログ確認・反射検出 |
| 1.5 | DOM-based XSS | `dom_xss` | DOM シンクフック |
| 1.5 | 格納型 XSS | `stored_xss` | マーカー注入後の横断検出 |
| 1.5 | 危険な JavaScript 静的評価 | `js_static` | source-to-sink 静的解析 |
| 1.6 | CSRF | `csrf` | POST フォームのトークン有無 |
| 1.7 | HTTP ヘッダインジェクション | `header_injection` | CRLF 注入とレスポンスヘッダ確認 |
| 1.8 | メールヘッダインジェクション | `mail_header` | 反射・エラー漏えい。OOB 設定時は注入 Bcc の到達を確証 |
| 1.9 | クリックジャッキング | `clickjacking` | X-Frame-Options / CSP `frame-ancestors` |
| 1.11 | オープンリダイレクト | `open_redirect` | リダイレクト先検証 |

このほか、権限昇格/IDOR、CORS、情報漏洩、Host ヘッダ、セキュリティヘッダ、NoSQL、デシリアライズ、リクエストスマグリング、SSRF、GraphQL、JWT、CMS、XXE、LDAP、ファイルアップロード、Race Condition、WebSocket、シークレット漏洩、SRI、Prototype Pollution、Cache Poisoning/Deception、Mass Assignment を検査できます。

## 2. 主要スクリーンショット

ダッシュボードで検査条件を入力し、実行前にスコープ・認証・チェック種別を確認できます。

![設定入力済みのダッシュボード](docs/images/dashboard-configured.png)

実行中の通信、進捗、スクリーンショット、Finding を同じ画面で確認できます。

![検査結果を表示したダッシュボード](docs/images/dashboard-results.png)

## 3. クイックスタート

### 通常モード — 最短手順

```bash
git clone https://github.com/oudontabetai1-lab/AutoXSScheckTool.git
cd AutoXSScheckTool
python3 -m pip install -r requirements.txt
playwright install chromium

python3 main.py scan https://example.com --headless --llm none
```

ダッシュボードから開始する場合:

```bash
python3 main.py serve --host 127.0.0.1 --port 8765
```

ブラウザで `http://localhost:8765/` を開き、「新規スキャン」から設定します。

### Agent モード — 最短手順

```bash
python3 -m pip install -r requirements-agent.txt
export ANTHROPIC_API_KEY="<api-key>"
export WSCAN_BEARER="<target-token>"
python3 main.py agent https://example.com --llm claude --headless \
  --bearer "$WSCAN_BEARER"
```

`agent` は `--bearer`、`-H/--header`、`--header-file` を Agent ブラウザへ適用します。Agent/Hybrid Phase 1 では、対応する browser-use 環境なら CDP `Fetch` で全リクエストを傍受し、各リクエスト URL が明示された target/access スコープのオリジンに属する場合だけ認証ヘッダを付与します。このため、第三者オリジンのサブリソースや外部へのリダイレクト／遷移には認証ヘッダを付与しません。

通常ツール層で認証ヘッダをオリジン単位にスコープ制御する場合は、全リクエストを Playwright `route` に通すため Service Worker を無効化します。

> ⚠️ **WebSocket 認証の制約**: 認証ヘッダのスコープ制御が有効な間、Playwright の `context.route()` が WebSocket のアップグレード要求を傍受しないため、WebSocket ハンドシェイクには Bearer/カスタム認証ヘッダが付きません。`route_web_socket()` でもハンドシェイクヘッダは変更できません。WS 認証が必要な対象や `websocket` スキャナを使う場合は、`config/wscan.yaml` の `browser.header_scope_enforce: false` または環境変数 `WSCAN_HEADER_SCOPE_ENFORCE=0` を指定してください。これは従来のコンテキスト全体適用へ戻す逃げ道であり、第三者サブリソースにも認証ヘッダが送信されるため、対象専用かつ最小権限のトークンを使用してください。既定値は `true` で、通常のスコープ制御は変わりません。

> ⚠️ **残存リスク**: Agent 層は対応する browser-use / cdp_use では新 target を停止状態で検知し、`Fetch.enable` 後に再開します。イベント購読 API が利用できない場合は各ステップ開始時の未設定 target 検出を継続しますが、新 target の初回リクエストには間に合わず、追加認証ヘッダなしで送信される可能性があります（フェイルクローズ）。初期 target で `Fetch.enable` 自体ができない場合は、探索を停止せず従来の CDP `Network.setExtraHTTPHeaders` 方式へフォールバックします。この方式ではブラウザターゲットの全リクエストにヘッダが適用されるため、第三者サブリソースや1ステップ内の外部リダイレクト／遷移へ送信される可能性が残ります。通常ツール層（`scan`）も Playwright `route` によりリクエスト単位でオリジンを判定し、route 登録に失敗した環境ではコンテキスト全体適用へフォールバックします。**フォールバック環境や外部リソースを多数読み込む対象で高権限トークンを使う場合は、影響範囲を絞ったトークンを用意してください。**Agent が申告する Finding は、決定論 Finding と同じ確証を意味しません。HTML レポートの「🤖 Agent発見」バッジと証拠を確認してください。

### Hybrid モード — 最短手順

Hybrid は現在ダッシュボードから開始します。

```bash
python3 -m pip install -r requirements-agent.txt
export ANTHROPIC_API_KEY="<api-key>"
python3 main.py serve --host 127.0.0.1 --port 8765
```

1. `http://localhost:8765/monitor` を開く。
2. 「基本設定」「検査項目」「認証・Cookie」を設定する。
3. 「ハイブリッド」タブで偵察用 LLM とステップ数を設定する。
4. 「ハイブリッドスキャン開始」を押す。

![ハイブリッド設定タブ](docs/images/dashboard-hybrid.png)

## 4. インストール

### 本体

Python 3.11 以上を推奨します。

```bash
git clone https://github.com/oudontabetai1-lab/AutoXSScheckTool.git
cd AutoXSScheckTool
python3 -m pip install -r requirements.txt
playwright install chromium
```

### Agent / Hybrid の追加依存

```bash
python3 -m pip install -r requirements-agent.txt
```

`browser-use` と、Claude/OpenAI/OpenAI 互換/Ollama のいずれかを準備します。ダッシュボードの Agent/Hybrid タブで選択できるプロバイダーは Claude、OpenAI、Ollama です。CLI の `agent` は `openai_compatible` も選択できます。

### MCP / OOB メール

MFA コード取得や blind XSS/SSRF・メールヘッダ注入の OOB 確証を使う場合:

```bash
python3 -m pip install -r requirements-mcp.txt
```

TOTP はネイティブ生成を利用でき、従来の `mcp-totp-authenticator` も互換経路として残っています。メール MFA は `mcp-email-server` を使います。OOB メールの環境変数と受信ボックスは [OOB メール設定](docs/oob_email_ja.md) を参照してください。API キー、TOTP シークレット、メールパスワードはリポジトリや YAML に保存しないでください。

## 5. ダッシュボード

### ポータル

```bash
python3 main.py serve --host 127.0.0.1 --port 8765
```

- `/` は Server Portal です。現在のスキャン、履歴、保存済みレポート、定期スキャン、監査ログ、通知設定を扱います。
- `/monitor` は設定画面兼ライブモニターです。
- `--auth-token` または `WSCAN_AUTH_TOKEN` を設定すると、Web UI はログインを要求し、API は `Authorization: Bearer <token>` を要求します。
- `0.0.0.0` はイントラネットから到達できる既定値です。ローカル限定なら `--host 127.0.0.1` を指定してください。

### 通常設定

| タブ | 主な内容 |
| --- | --- |
| 基本設定 | Depth、Timeout、Max Forms、並列数、ペイロード上限、遅延、遷移リトライ、プロキシ、TLS、Headless |
| 検査項目 | 実行する決定論スキャナ |
| 認証・Cookie | Cookie、自動ログイン、低権限 Cookie、ネイティブ TOTP、Bearer/カスタムヘッダ、複数アカウント |
| LLM設定 | provider、モデル、互換ベース URL、役割別モデル |
| 機能フラグ | Planner、AI 分析、WAF、学習、community ペイロード、sitemap、SPA、巡回レビューなど |
| スコープ・除外 | 攻撃対象、アクセスのみ許可、除外 URL、除外フィールド |
| 手動巡回 | 可視ブラウザ、遠隔ブラウザ、URL リストから巡回シードを作成 |
| 攻撃フロー | navigate / fill / click / wait 等の複数手順 |

「スキャン開始」は通常モードです。`planner.interactive=true` または画面の攻撃プラン確認を有効にした場合、巡回後にフィールド、チェック、カスタムペイロードを確認してから攻撃へ進みます。

認証タブの TOTP は `otpauth://` URI、Base32 シークレット、QR 画像からサーバー内でローカル生成します。Bearer トークンまたは1行1件のカスタムヘッダは、通常ツール層（`scan`）の crawl と全 HTTP リクエストに加え、Agent モードと Hybrid Phase 1 の Agent 偵察にも適用されます。明示した `Authorization` ヘッダは Bearer 欄より優先されます。TOTP URI/シークレットと Bearer は設定 export やブラウザ保存へ含めません。任意コマンドを実行する `header_refresh_cmd` はサーバー配備時の RCE 面になるため、ダッシュボードには公開していません。

サーバー配備時は、TLS 証明書/秘密鍵/PFX/CA、カスタムペイロード、手動巡回 JSON、TOTP QR をブラウザからアップロードできます。保存先は `output/uploads/`、上限は1ファイル 8MBです。拡張子は用途別に制限され、既存のサーバー側パス入力も後方互換で利用できます。出力ディレクトリと手動巡回の保存先はアップロード対象ではないため、リモート運用では空欄（自動）を推奨します。

### Agent タブ

Agent は LLM がページを観察し、操作、ペイロード選択、結果判断を行います。プロバイダー、モデル、最大ステップ数、検査種別、ログイン情報を設定して「Agent Browser スキャン開始」を押します。通常モードの決定論判定とは品質基準が異なり、独自性を優先します。

### Hybrid タブ

偵察用 LLM、モデル、Ollama URL、最大ステップ数を設定します。認証情報と検査項目は通常設定のタブから引き継ぎます。Phase 1 の URL と Agent Finding を Phase 2 に渡し、通常スキャンの Finding と一緒に最終レポートへ出します。

![通常・Agent・Hybrid を切り替える設定画面](docs/images/dashboard-hybrid.png)

### 実行中・結果

実行中は Crawl / Plan / Attack / Report のフェーズ、巡回マップ、ブラウザ画面、チェック進捗、現在の URL/Field/Check/Payload、Findings、Request/Response、Event Log を確認できます。一時停止、再開、フィールド/ページのスキップ、中断、手動ペイロード実行も利用できます。中断時はその時点までの部分レポートを保存します。

詳しい画面操作は [ダッシュボード利用ガイド](docs/dashboard_usage_ja.md) を参照してください。

## 6. CLI リファレンス

現在のサブコマンドは次の 9 個です。

```text
scan agent triage serve setup batch record manual-crawl import-payloads
```

正確なローカル既定値は `config/wscan.yaml` の影響を受けます。実行環境では次も確認してください。

```bash
python3 main.py --help
python3 main.py scan --help
```

### `scan` — 通常スキャン

```bash
python3 main.py scan URL [options]
```

基本・LLM:

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `URL` | 必須 | 検査対象 URL |
| `-p, --payloads FILE` | `output.payloads_file` / なし | カスタムペイロード YAML |
| `--checks CHECK...` | `sqli xss os` | 実行するチェック。選択肢は「対応チェック種別」参照 |
| `-d, --depth N` | `2` | クロール深度 |
| `--headless` | `browser.headless` (`false`) | ブラウザ非表示 |
| `--no-monitor` | monitor 有効 | ライブモニターを無効化 |
| `--llm PROVIDER` | `ollama` | `ollama/claude/openai/openai_compatible/gemini/none` |
| `--ollama-model MODEL` | `llama3` | Ollama モデル |
| `--openai-model MODEL` | `gpt-4o-mini` | OpenAI / OpenAI 互換モデル |
| `--llm-base-url URL` | 空 | OpenAI 互換 API のベース URL |
| `--gemini-model MODEL` | `gemini-2.0-flash` | Gemini モデル |
| `--claude-model MODEL` | `claude-haiku-4-5-20251001` | Claude モデル |
| `--planner-model MODEL` | provider モデル | 計画用モデル上書き |
| `--payload-model MODEL` | provider モデル | ペイロード生成用モデル上書き |
| `--adaptive-model MODEL` | provider モデル | 適応ペイロード用モデル上書き |
| `--triage-model MODEL` | provider モデル | トリアージ用モデル上書き |
| `--report-model MODEL` | provider モデル | 分析・修正提案用モデル上書き |
| `-o, --output DIR` | `output/<timestamp>/` | 証跡・レポート出力先 |
| `--port PORT` | `8765` | モニターポート |
| `--timeout SECS` | `30` | リクエストタイムアウト |
| `--max-forms N` | `50` | 1ページの最大フォーム数 |

スコープ・認証・通信:

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `-e, --exclude PARAM...` | `[]` | 除外フィールド名 |
| `--exclude-file FILE` | なし | 除外フィールドを1行1件で読む |
| `--exclude-urls-file FILE` | なし | 除外 URL/プレフィックスを1行1件で読む |
| `--target-url URL_OR_PREFIX` | なし | 巡回・攻撃対象を追加。複数指定可 |
| `--target-urls-file FILE` | なし | 追加攻撃対象をファイルで指定 |
| `--access-url URL_OR_PREFIX` | なし | 到達は許可するが攻撃しない範囲。複数指定可 |
| `--access-urls-file FILE` | なし | アクセスのみ許可する範囲をファイルで指定 |
| `--cookie COOKIES` | 空 | `name=value; ...` 形式の Cookie |
| `--cookie-file FILE` | 空 | ブラウザエクスポート形式の Cookie JSON |
| `--low-priv-cookies COOKIES` | 空 | 垂直権限昇格検査用の低権限 Cookie |
| `--low-priv-cookie-file FILE` | 空 | 低権限 Cookie JSON |
| `-H, --header "Name: Value"` | `[]` | 全リクエストに追加。複数指定可 |
| `--header-file FILE` | 空 | JSON/YAML/1行1ヘッダ形式 |
| `--header-refresh-cmd CMD` | 空 | stdout からヘッダを更新するコマンド |
| `--header-refresh-interval SECONDS` | `0` | ヘッダ更新間隔。0 は無効 |
| `--bearer TOKEN` | 空 | `Authorization: Bearer TOKEN` を全リクエストへ付与 |
| `--auth-user USER` / `--auth-pass PASS` | config / 空 | ログインフォーム用資格情報 |
| `--login-url URL` | 空 | 自動ログイン URL |
| `--login-user-field NAME` | `username` | ユーザー名入力欄 |
| `--login-pass-field NAME` | `password` | パスワード入力欄 |
| `--login-success TEXT` | 空 | 成功確認用の URL/ページ内文字列 |
| `--mfa-type totp\|email` | 未指定 | ネイティブ TOTP または外部 MCP で MFA コード取得 |
| `--mfa-field NAME` | 空（実行時既定 `otp`） | MFA 入力欄の name/id |
| `--mfa-totp-uri URI` | 空 | `otpauth://totp/...` からネイティブ TOTP を生成 |
| `--mfa-totp-secret BASE32` | 空 | 生 Base32 シークレットからネイティブ TOTP を生成 |
| `--mfa-totp-qr FILE` | 空 | QR 画像からネイティブ TOTP を生成（opencv は任意依存） |
| `--mfa-totp-digits N` | `6` | 生 Base32 / QR 用の TOTP 桁数 |
| `--mfa-totp-period SEC` | `30` | 生 Base32 / QR 用の TOTP 周期秒 |
| `--mfa-totp-algorithm ALG` | `SHA1` | 生 Base32 / QR 用のハッシュ（SHA1/SHA256/SHA512） |
| `--mfa-email-account EMAIL` | 空 | 登録済み `account_name` |
| `--mfa-email-address EMAIL` | 空 | 動的 IMAP のメールアドレス |
| `--mfa-email-imap-host HOST` | 空 | 動的 IMAP の受信ホスト |
| `--mfa-email-imap-port PORT` | 空（実行時既定 `993`） | IMAP ポート |
| `--mfa-email-imap-user USER` | 空（実行時はアドレス） | IMAP ユーザー |
| `--mfa-email-imap-password PASS` | 空 | IMAP パスワード。環境変数推奨 |
| `--mfa-email-imap-ssl true\|false` | 未指定（実行時 `true`） | IMAP SSL |
| `--include-registration` | 登録フォームを除外 | 登録/サインアップも検査 |
| `--allow-state-changing-probes` | 無効 | 状態変更し得る権限昇格プローブを許可 |
| `--accounts USER:PASS,...` | 空 | 複数アカウント権限昇格検査 |
| `--accounts-file FILE` | 空 | `accounts:` 配列を持つ YAML |
| `--auto-register` | 無効 | テストアカウント自動登録 |
| `--auto-register-count N` | `2` | 自動登録数 |
| `--proxy URL` | 空 | Browser/httpx の HTTP プロキシ |
| `--tls-client-cert FILE` / `--tls-client-key FILE` | 空 | mTLS 用 PEM 証明書/秘密鍵 |
| `--tls-client-pfx FILE` | 空 | Playwright 用 PFX/PKCS#12 |
| `--tls-client-cert-password TEXT` | 空 | 証明書/PFX パスフレーズ |
| `--tls-ca-cert FILE` | 空 | httpx の CA バンドル |
| `--tls-verify` | `false` | httpx のサーバ証明書検証を有効化 |

検査制御・出力:

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `--ctf` | `false` | SSTI を追加し待機を短縮 |
| `--ctf-flag-format REGEX` | 自動検出 | Flag 正規表現 |
| `--no-planner` | planner 有効 | AI 攻撃計画を無効化 |
| `--interactive-plan` | `false` | 攻撃前に計画を編集 |
| `--no-open-report` | 自動表示有効 | 完了時の HTML 自動表示を無効化 |
| `--learning-file FILE` | `config/payload_learning.json` | 学習データファイル |
| `--dom-xss` | `false` | DOM-based XSS を追加 |
| `--no-ai-analysis` | 有効 | スキャン後 AI 分析を無効化 |
| `--no-waf-detection` | 有効 | WAF 検出を無効化 |
| `--no-payload-learning` | 有効 | 成功率学習を無効化 |
| `--community-payloads / --no-community-payloads` | `true` | 生成済み公開ペイロードを使用/不使用 |
| `--no-adaptive-payloads` | adaptive 有効 | LLM 適応ラウンドを無効化 |
| `--no-sitemap-crawl` | 有効 | sitemap/robots シードを無効化 |
| `-j, --concurrency N` | `1` | 攻撃フェーズの並列ブラウザ数。推奨 2〜4 |
| `-F, --fast` | `false` | 深さ1、上限12、遅延0等の高速プリセット |
| `--max-payloads N` | `0`（無制限） | フィールド×チェックの標準ペイロード上限 |
| `--delay SECS` | `0.5` | リクエスト間隔 |
| `--navigation-retries N` | `2` | ページ遷移の再試行回数 |
| `--no-sarif` | SARIF 有効 | `report.sarif` を出力しない |
| `--notify-webhook URL` | 空 | Finding 通知の Slack/汎用 Webhook |
| `--notify-severity LEVEL` | `high` | `critical/high/medium/low` の通知閾値 |
| `--har FILE` | 空 | HAR の URL/Cookie をシード化 |
| `--manual-crawl FILE` | config / 空 | 手動巡回 JSON をシード化 |
| `--api-spec FILE` | 空 | OpenAPI/Swagger/Postman を直接検査 |
| `--resume DIR` | 空 | 前回の `checkpoint.json` から再開 |
| `--no-checkpoint` | 保存有効 | チェックポイントを無効化 |
| `--allowed-hours WINDOW` | なし | 許可時間帯。複数指定可 |
| `--forbidden-hours WINDOW` | なし | 禁止時間帯。複数指定可 |
| `--no-relogin` | 自動再ログイン有効 | セッション失効時の再ログインを無効化 |
| `--logged-in-marker TEXT` | `--login-success` を流用 | 認証済み判定文字列 |
| `--spa-crawl` | `false` | SPA の動的ルートを探索 |
| `--previous-scan DIR` | なし | 前回 `evidence.json` と差分比較 |
| `--auto-config / --no-auto-config` | `false` | 起動時の設定ウィザード |

### `agent` — Agent Browser

```bash
python3 main.py agent URL [options]
```

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `--llm` | `claude` | `claude/openai/openai_compatible/ollama` |
| `--llm-base-url URL` | 空 | OpenAI 互換ベース URL |
| `--model MODEL` | provider 既定 | Agent 用モデル |
| `--ollama-url URL` | `http://localhost:11434` | Ollama API |
| `--checks CHECK...` | `xss sqli ssti os path_traversal ssrf` | Agent の検査種別 |
| `--max-steps N` | `100` | 最大操作ステップ |
| `--headless / --no-headless` | headless | 非表示/表示ブラウザ |
| `--auth-user`, `--auth-pass`, `--login-url` | config / 空 | 事前ログイン |
| `--bearer TOKEN` | `WSCAN_BEARER` / config / 空 | Agent ブラウザへ Bearer 認証を付与 |
| `-H, --header "Name: Value"` | `[]` | Agent ブラウザへカスタムヘッダを追加。複数指定可 |
| `--header-file FILE` | 空 | JSON/YAML/1行1ヘッダ形式 |
| `-o, --output DIR` | `output/agent_<timestamp>/` | 出力先 |
| `--port PORT` | `8765` | モニターポート |
| `--no-monitor`, `--no-open-report` | 無効 | モニター/自動表示を無効化 |

### `triage` — ペイロード非投入の高速評価

```bash
python3 main.py triage URL [options]
```

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `-d, --depth N` | `2` | クロール深度 |
| `--headless` | `true` | ヘッドレス実行 |
| `--proxy URL` | 空 | HTTP プロキシ |
| `--timeout SECS` | config の `30` | ページタイムアウト |
| `--llm` | `llm.provider` (`ollama`) | 戦略インサイト用 provider。`none` 可 |
| 各 `--*-model` / `--llm-base-url` | config / provider 既定 | モデルと互換 URL |
| `-o, --output FILE` | なし | JSON 保存先 |

### `serve` — ダッシュボード常駐

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `--port PORT` | `8765` | HTTP/WebSocket ポート |
| `--host ADDR` | `0.0.0.0` | バインド先。`WSCAN_HOST` が優先 |
| `--auth-token TOKEN` | 空 | 共有トークン。`WSCAN_AUTH_TOKEN` が優先 |
| `--insecure` | 無効 | 公開 IP への無認証バインドを明示許可。非推奨 |
| `--open-browser / --no-open-browser` | localhost 時のみ自動 | ホスト側ブラウザの起動制御 |

### `setup` — 自然言語設定支援

```bash
python3 main.py setup "ECサイト。管理画面とREST APIあり"
```

`description` は省略時に対話入力します。`--llm`、`--ollama-model`、`--ollama-url`、`--openai-model`、`--llm-base-url` を指定できます。説明からチェック、深さ、追加フラグを選んだ推奨 `scan` コマンドを表示します。

### `batch` — 複数ターゲット

```bash
python3 main.py batch TARGETS_YAML [-o DIR]
```

ターゲット YAML を順番に実行し、統合サマリーを生成します。出力先の既定は `output/batch_<timestamp>/` です。

### `record` — 操作フロー記録

```bash
python3 main.py record URL [--output flows/recording.json] [--headless]
```

ブラウザ操作を再生可能な JSON フローとして記録します。画面を操作する場合は `--headless` を付けません。

### `manual-crawl` — 手動巡回シード

```bash
python3 main.py manual-crawl URL [--output flows/manual_crawl.json] [--headless] [--proxy URL]
```

訪問 URL、フォーム、Cookie をスキャン用シード JSON に保存します。

### `import-payloads` — 公開ペイロード取り込み

```bash
python3 main.py import-payloads [options]
```

| オプション | 既定 | 内容 |
| --- | --- | --- |
| `--output FILE` | `config/community_payloads.yaml` | 保存先 |
| `--allow-destructive` | 無効 | 既定で除外する破壊的パターンも保持 |
| `--per-type-cap N` | なし | チェック種別ごとの上限 |
| `--check xss,sqli` | 全対応ソース | 取り込む種別を限定 |

取り込み時だけネットワークを使用し、スキャン時は生成済み YAML を読みます。

## 7. 設定リファレンス

`config/wscan.yaml` は CLI とダッシュボードの既定値です。明示した CLI/UI 値が優先します。型は YAML 上の型、既定値は現行ファイルの値です。`accounts:` と `notifications:` は設定ローダーへ接続されていないため、この表には載せません。複数アカウントは CLI/UI、通知は CLI またはポータルの通知設定を使用してください。

対応欄の「UI」はダッシュボード、「serve」はサーバー起動オプション、「—」は直接対応する CLI/UI がないことを示します。

### `scan`

| キー | 型 | 既定値 | 対応 CLI / UI |
| --- | --- | --- | --- |
| `scan.checks` | list[str] | `[sqli, xss, os]` | `--checks` / 検査項目 |
| `scan.depth` | int | `2` | `--depth` / 基本設定 |
| `scan.max_forms` | int | `50` | `--max-forms` / 基本設定 |
| `scan.timeout` | int | `30` | `--timeout` / 基本設定 |
| `scan.exclude_fields` | list[str] | `[]` | `--exclude`, `--exclude-file` / スコープ・除外 |
| `scan.exclude_urls` | list[str] | `[]` | `--exclude-urls-file` / スコープ・除外 |
| `scan.target_urls` | list[str] | `[]` | `--target-url`, `--target-urls-file` / スコープ・除外 |
| `scan.access_urls` | list[str] | `[]` | `--access-url`, `--access-urls-file` / スコープ・除外 |
| `scan.manual_crawl_file` | str | `""` | `--manual-crawl` / 手動巡回 |
| `scan.request_delay` | float | `0.5` | `--delay` / 基本設定 |
| `scan.navigation_retries` | int | `2` | `--navigation-retries` / 基本設定 |

状態変更し得る権限昇格プローブは YAML の有効キーではなく、`--allow-state-changing-probes` またはダッシュボードで明示的に許可します。

### `browser`

| キー | 型 | 既定値 | 対応 CLI / UI |
| --- | --- | --- | --- |
| `browser.headless` | bool | `false` | `--headless` / 基本設定 |
| `browser.proxy` | str | `""` | `--proxy` / 基本設定 |
| `browser.tls_client_cert` | str | `""` | `--tls-client-cert` / 基本設定 |
| `browser.tls_client_key` | str | `""` | `--tls-client-key` / 基本設定 |
| `browser.tls_client_pfx` | str | `""` | `--tls-client-pfx` / 基本設定 |
| `browser.tls_client_cert_password` | str | `""` | `--tls-client-cert-password` / 基本設定 |
| `browser.tls_ca_cert` | str | `""` | `--tls-ca-cert` / 基本設定 |
| `browser.tls_verify` | bool | `false` | `--tls-verify` / 基本設定 |
| `browser.header_scope_enforce` | bool | `true` | `WSCAN_HEADER_SCOPE_ENFORCE=0` で無効化 |

### `llm`

| キー | 型 | 既定値 | 対応 CLI / UI |
| --- | --- | --- | --- |
| `llm.provider` | str | `ollama` | `--llm` / LLM設定 |
| `llm.timeout_seconds` | int | `30` | — |
| `llm.max_retries` | int | `2` | — |
| `llm.ollama_model` | str | `llama3` | `--ollama-model` / LLM設定 |
| `llm.ollama_url` | str | `http://localhost:11434` | Agent/Setup の `--ollama-url` / Agent・Hybrid設定 |
| `llm.openai_model` | str | `gpt-4o-mini` | `--openai-model` / LLM設定 |
| `llm.openai_base_url` | str | `""` | `--llm-base-url` / LLM設定（OpenAI互換時） |
| `llm.gemini_model` | str | `gemini-2.0-flash` | `--gemini-model` / LLM設定 |
| `llm.models` | map[str,str] | `{}` | `--planner-model`, `--payload-model`, `--adaptive-model`, `--triage-model`, `--report-model` / LLM設定 |

`llm.models` のキーは `planner`、`payload`、`adaptive`、`triage`、`report` です。未指定なら provider のモデルを使います。

### `monitor`

| キー | 型 | 既定値 | 対応 CLI / UI |
| --- | --- | --- | --- |
| `monitor.enabled` | bool | `true` | `scan --no-monitor` |
| `monitor.port` | int | `8765` | `--port` / 表示のみ |
| `monitor.host` | str | `0.0.0.0` | `serve --host` |
| `monitor.auth_token` | str | `""` | `serve --auth-token` |
| `monitor.retention_days` | number | `0` | ポータル保持ポリシー / `WSCAN_RETENTION_DAYS` |
| `monitor.retention_max_scans` | int | `0` | ポータル保持ポリシー / `WSCAN_RETENTION_MAX_SCANS` |
| `monitor.allowed_target_hosts` | list[str] | `[]` | serve の対象制限 / `WSCAN_ALLOWED_HOSTS` |
| `monitor.denied_target_hosts` | list[str] | `[]` | serve の拒否対象 / `WSCAN_DENIED_HOSTS` |
| `monitor.scan_timeout_minutes` | number | `0` | watchdog / `WSCAN_SCAN_TIMEOUT_MIN` |
| `monitor.trust_proxy` | bool | `false` | `WSCAN_TRUST_PROXY=1` |

`0` は保持日数・件数・watchdog の制限なしです。`denied_target_hosts` は `allowed_target_hosts` より優先します。`trust_proxy=true` は信頼できるリバースプロキシ配下でのみ使用してください。

### `planner` / `auth`

| キー | 型 | 既定値 | 対応 CLI / UI |
| --- | --- | --- | --- |
| `planner.enabled` | bool | `true` | `--no-planner` / 機能フラグ |
| `planner.interactive` | bool | `false` | `--interactive-plan` / 機能フラグ |
| `auth.login_url` | str | `""` | `--login-url` / 認証・Cookie |
| `auth.login_user_field` | str | `username` | `--login-user-field` / 認証・Cookie |
| `auth.login_pass_field` | str | `password` | `--login-pass-field` / 認証・Cookie |
| `auth.login_success_indicator` | str | `""` | `--login-success` / 認証・Cookie |
| `auth.auth_user` | str | `""` | `--auth-user` / 認証・Cookie |
| `auth.auth_pass` | str | `""` | `--auth-pass` / 認証・Cookie |
| `auth.mfa_type` | str | `""` | `--mfa-type` / 認証・Cookie |
| `auth.mfa_field` | str | `""` | `--mfa-field` / 認証・Cookie |

平文パスワードを YAML に保存しないでください。ダッシュボードから送った秘匿フィールドは `scan_config.json` で伏字化されます。

### `features`

| キー | 型 | 既定値 | 対応 CLI / UI |
| --- | --- | --- | --- |
| `features.dom_xss` | bool | `false` | `--dom-xss` / 検査項目・機能フラグ |
| `features.ai_analysis` | bool | `true` | `--no-ai-analysis` / 機能フラグ |
| `features.waf_detection` | bool | `true` | `--no-waf-detection` / 機能フラグ |
| `features.payload_learning` | bool | `true` | `--no-payload-learning` / 機能フラグ |
| `features.payload_evolution` | bool | `true` | YAML（LLM不要の文脈適応 wave） |
| `features.payload_mutation` | bool | `true` | YAML（LLM不要の変異 wave） |
| `features.community_payloads` | bool | `true` | `--community-payloads/--no-community-payloads` |
| `features.sitemap_crawl` | bool | `true` | `--no-sitemap-crawl` / 機能フラグ |
| `features.cvss_scores` | bool | `true` | YAML（レポート表示） |
| `features.skip_registration` | bool | `true` | `--include-registration` / 機能フラグ |
| `features.open_report` | bool | `true` | `--no-open-report` / 機能フラグ |
| `features.auto_config` | bool | `false` | `--auto-config/--no-auto-config` |
| `features.spa_crawl` | bool | `false` | `--spa-crawl` / 機能フラグ |
| `features.interactive_crawl_review` | bool | `false` | ダッシュボードの巡回レビュー |

### `learning` / `ctf` / `output`

| キー | 型 | 既定値 | 対応 CLI / UI |
| --- | --- | --- | --- |
| `learning.file` | str | `""` | `--learning-file` |
| `ctf.enabled` | bool | `false` | `--ctf` / 機能フラグ |
| `ctf.flag_pattern` | str | `""` | `--ctf-flag-format` |
| `output.dir` | str | `""` | `--output` |
| `output.payloads_file` | str | `""` | `--payloads` |

## 8. LLM アーキテクチャ

### provider と必要な設定

| provider | 用途・接続 | 認証 |
| --- | --- | --- |
| `ollama` | ローカル `/api/generate` | 通常不要 |
| `claude` | Anthropic API | `ANTHROPIC_API_KEY` |
| `openai` | 公式 OpenAI chat completions | `OPENAI_API_KEY` |
| `openai_compatible` | tsuzumi 2、Azure AI Foundry、vLLM、LiteLLM、LM Studio 等 | `WSCAN_LLM_API_KEY`、なければ `OPENAI_API_KEY` |
| `gemini` | Google `generateContent` | `GEMINI_API_KEY` |
| `none` | LLM を呼ばない | 不要 |

OpenAI 互換のベース URL は `--llm-base-url`、`llm.openai_base_url`、ダッシュボード、`WSCAN_LLM_BASE_URL`（または `OPENAI_BASE_URL`）で指定します。公式 `openai` と互換 provider を分離し、長時間の `serve` プロセスで互換 URL が別スキャンの公式 OpenAI 呼び出しへ漏れないよう、エンジンごとに明示的に保持します。

```bash
export WSCAN_LLM_BASE_URL="https://your-host/v1"
export WSCAN_LLM_API_KEY="<api-key>"
python3 main.py scan https://example.com \
  --llm openai_compatible --openai-model tsuzumi-2 --headless
```

### `llm_client` による一元化

ペイロード、adaptive、レポート分析、修正提案などの生テキスト LLM 呼び出しは共通クライアントを使います。`llm.timeout_seconds` は1回のタイムアウト、`llm.max_retries` は初回の後に行う最大リトライ回数です。役割別モデルは呼び出し前に切り替えます。

一時失敗として再試行するのは、HTTP `408/429/500/502/503/504/529`、接続・読み書き・タイムアウト・プロトコルエラー、Anthropic の接続/タイムアウトラッパー、成功ステータスでも一時的に壊れたレスポンス形式です。`Retry-After` を尊重し、なければ指数バックオフします。認証失敗などの恒久エラーは繰り返しません。

### fallback

- payload: 手キュレーションの `default_payloads.yaml`、生成済み community、LLM 不要の evolution/mutation を継続します。
- planner: LLM 応答が利用できなければヒューリスティック計画へ戻ります。
- remediation: LLM 生成に失敗した場合は脆弱性種別ごとの静的修正テンプレートを使います。
- Gemini: 共通クライアントから remediation を生成でき、利用不可時は同じ静的 fallback へ戻ります。
- adaptive: 一時失敗と恒久的な provider 不達を区別します。詳細は次の「長時間スキャン・見逃し防止」を参照してください。

## 9. Finding の読み方

Finding は「検出した」という一点だけでなく、出自、再現状態、確信度、証拠種別を分けて読みます。

| フィールド | 値 | 読み方 |
| --- | --- | --- |
| `source` | `scanner` / `agent` | 決定論スキャナ由来か Agent の独自解釈か |
| `verified` | bool | 2回目の再現に成功したか。`false` なら `verification_note` も確認 |
| `confidence` | `confirmed` / `likely` / `tentative` | 証拠の強さ。重要度 `severity` とは別軸 |
| `evidence_type` | 例: `xss_dialog`, `sqli_error` | どの構造化シグナルで判定したか |
| `agent_verified` | bool | Agent Finding を決定論的にも再現確認できたか |

HTML レポートでは、`source=agent` の Finding を次のバッジで区別します。

- `🤖 Agent発見（LLM独自解釈・未確証）`: Agent の仮説。未確証でも独自性を保つためレポートから消しません。
- `🤖 Agent発見（LLM独自解釈）` + `✅ 決定論的にも再現確認済み`: `agent_verified=true` の Agent Finding。
- バッジなし: 通常の決定論スキャナ由来。

Agent Finding は変換時に `source=agent`、`verified=false` となります。`severity` が高くても、Agent 未確証バッジがあれば証拠、Request/Response、再現手順を人手で確認してください。逆に通常 Finding でも `confidence=tentative` や `verified=false` なら確証済みとは扱いません。

SARIF の `result.properties` にも `source`、`agent_verified`、`verified`、`confidence` を保存し、fingerprint に `source` を含めます。

## 10. Hybrid フロー

![Hybrid モード設定](docs/images/dashboard-hybrid.png)

```text
Phase 1: Agent recon
  ├─ discovered_urls
  └─ Agent Finding (source=agent)
             │ handoff
             ▼
Phase 2: deterministic scan
  ├─ 発見 URL を seed_urls として巡回・攻撃
  └─ scanner Finding (source=scanner)
             │ merge
             ▼
最終 HTML / JSON / SARIF
  └─ Agent Finding と scanner Finding をラベル付きで併記
```

1. Agent Browser が対象を探索し、ターゲット URL を先頭に訪問 URL の重複を除いて収集します。
2. 探索中に Agent が脆弱性仮説を申告した場合、標準 `Finding` へ変換して URL と一緒に引き渡します。
3. 通常エンジンは発見 URL を巡回シードとして、選択された決定論スキャナを実行します。
4. レポート生成前に Agent Finding を通常 Finding へ追加し、出自ラベル付きで併記します。

Phase 1 が失敗した場合、ダッシュボードは警告を出し、URL シードと Agent Finding なしで通常スキャンを続行します。Hybrid は「Agent は偵察のみ」ではありませんが、Agent Finding 自体が自動的に決定論的確証へ変わるわけでもありません。

## 11. 長時間スキャン・見逃し防止

### checkpoint / resume

通常スキャンは既定で `output/<timestamp>/checkpoint.json` に進捗と既出 Finding を保存します。通常攻撃は `(URL × フィールド × フォーム位置 × チェック種別)` の単位で完了を記録し、例外で終わった単位は未完了のまま残します。

```bash
python3 main.py scan https://example.com \
  --allowed-hours "Mon-Fri 22:00-06:00" \
  --forbidden-hours "Mon-Fri 09:00-18:00"

python3 main.py scan https://example.com \
  --resume output/20260721_010203
```

`--resume` はターゲットとチェック構成の互換性を確認し、完了単位を飛ばして残りだけを実行します。`--no-checkpoint` で保存を無効化できます。

### adaptive のチェック種別単位回収

adaptive LLM ラウンドはフィールド全体を一括完了にせず、`field × check_type` ごとに checkpoint を記録します。一部のチェックで payload 生成、ブラウザ操作、スキャナ実行が一時失敗しても、成功済みチェックは保持し、失敗したチェックだけを `--resume` で再試行します。空/空白の LLM 応答も一時失敗として未完了にします。

一方、スキャン中に一度行う可用性確認で provider 自体が恒久的に利用できないと判断した場合は、adaptive を fallback 完了として記録します。これにより、決定論ペイロードでスキャンを完了させつつ、到達不能な LLM を resume のたびに無限再試行しません。

### セッションと時間帯

長時間スキャンでは認証切れを 401、ログインフォーム残存などの強いシグナルから検出し、既定で再ログインします。`--logged-in-marker` で精度を補強し、不要なら `--no-relogin` を指定します。許可/禁止時間帯では攻撃を待機し、再開可能な checkpoint を維持します。

## 12. 出力・連携

代表的な出力:

```text
output/<timestamp>/
├── report.html
├── report_executive.html
├── report_developer.html
├── report.sarif
├── evidence.json
├── reproduction.json
├── reproduce.sh
├── scan_config.json
├── checkpoint.json
├── remediation_plan.md
├── remediation_tasks.json
├── ai_analysis.md
├── ai_finding_fixes.json
├── http_requests.jsonl
├── payloads.jsonl
└── screenshots/
```

| 出力 | 用途 |
| --- | --- |
| `report.html` | 自己完結型 HTML。Finding、証拠、Agent バッジ、実行条件 |
| `report_executive.html` | 管理層向けサマリー |
| `report_developer.html` | 開発者向け詳細・修正観点 |
| `evidence.json` | Finding と証跡の機械可読 JSON |
| `reproduction.json`, `reproduce.sh` | 再現情報とコマンド |
| `report.sarif` | SARIF 2.1.0。`properties.source` 等を含む |
| `remediation_plan.md`, `remediation_tasks.json` | 修正計画とタスク |
| `http_requests.jsonl`, `payloads.jsonl` | 通信・投入ペイロード監査ログ。秘匿ヘッダ等はマスク |
| `scan_config.json` | 実行設定スナップショット。秘匿値は伏字 |

### Webhook

```bash
python3 main.py scan https://example.com \
  --notify-webhook https://hooks.example.invalid/... \
  --notify-severity high
```

Finding 検出時に Slack Incoming Webhook または汎用 JSON POST エンドポイントへ通知します。通知失敗でスキャン本体は停止しません。serve の通知設定はポータルから管理します。

### REST / WebSocket

`serve` は `/api/v1/scan`、`/api/v1/scan/status`、`/api/v1/scan/findings`、`/api/v1/scan/results`、`/api/v1/scans`、認証必須の `/api/v1/upload`、スケジュール・履歴・手動巡回 API と `/ws` を提供します。トークン設定時は Bearer 認証が必要です。`/health` は稼働確認に使えます。

### batch

`batch` は YAML に定義した複数 URL を順次実行し、個別成果物と統合サマリーを `output/batch_<timestamp>/` に保存します。

## 13. 認証・MFA・スコープ・TLS

### Cookie / ログイン / 権限昇格

```bash
python3 main.py scan https://example.com \
  --login-url https://example.com/login \
  --auth-user ops --auth-pass 'p@ss' \
  --login-user-field username --login-pass-field password \
  --login-success dashboard
```

ログイン成否は URL 変化だけでなく、ログインフォーム残存、失敗メッセージ、MFA 画面残留も確認します。Cookie を直接渡す場合は `--cookie` / `--cookie-file`、垂直権限昇格は `--low-priv-cookies` / `--low-priv-cookie-file`、複数アカウントは `--accounts` / `--accounts-file` を使用します。

`--allow-state-changing-probes` は POST/PUT/PATCH 等の状態変更を伴う可能性があります。変更してよい検証環境に限って有効にしてください。

### MFA

ここは確実性を重視する通常ツール層（`scan`）の認証付きスキャン補助です。脆弱性判定には影響せず、TOTP とメールコードをパスワード送信後の MFA 入力欄へ投入します。

TOTP は `otpauth://` URI、生 Base32、QR 画像のいずれかからネットワークなしで生成できます。`--mfa-totp-*` だけでも TOTP 方式へ自動昇格しますが、方式を明示する場合は次のように指定します。

```bash
export WSCAN_MFA_TOTP_URI='otpauth://totp/Example:ops?secret=<base32-secret>&issuer=Example'

python3 main.py scan https://example.com \
  --login-url https://example.com/login --auth-user ops --auth-pass 'p@ss' \
  --mfa-type totp --mfa-totp-uri "$WSCAN_MFA_TOTP_URI" --mfa-field otp
```

URI の代わりに `--mfa-totp-secret BASE32` または `--mfa-totp-qr code.png` も使えます。QR 読み取りだけは任意依存の opencv が必要です（`pip install opencv-python-headless`）。シークレットや URI は保存されないため、毎回 CLI または `WSCAN_MFA_TOTP_URI` / `WSCAN_MFA_TOTP_SECRET` / `WSCAN_MFA_TOTP_QR` で渡してください。

従来の外部 MCP による TOTP 取得も引き続き利用できます。

```bash
# TOTP
export WSCAN_MFA_TOTP_COMMAND="node"
export WSCAN_MFA_TOTP_ARGS="/opt/mcp-totp-authenticator/dist/index.js"
export WSCAN_MFA_TOTP_LABEL="ops@example.com"
export TOTP_SECRET_1="<base32-secret>"
export TOTP_LABEL_1="ops@example.com"

python3 main.py scan https://example.com \
  --login-url https://example.com/login --auth-user ops --auth-pass 'p@ss' \
  --mfa-type totp --mfa-field otp
```

登録済みメールアカウントを使う場合、`WSCAN_MFA_EMAIL_ACCOUNT` と `mcp-email-server` 側の `account_name` を一致させます。

```bash
export WSCAN_MFA_EMAIL_COMMAND="uvx"
export WSCAN_MFA_EMAIL_ARGS="mcp-email-server@latest stdio"
export WSCAN_MFA_EMAIL_ACCOUNT="ops"
export MCP_EMAIL_SERVER_ACCOUNT_NAME="ops"
export MCP_EMAIL_SERVER_EMAIL_ADDRESS="otp@example.com"
export MCP_EMAIL_SERVER_PASSWORD="<app-password>"
export MCP_EMAIL_SERVER_IMAP_HOST="imap.example.com"

python3 main.py scan https://example.com \
  --login-url https://example.com/login --auth-user ops --auth-pass 'p@ss' \
  --mfa-type email
```

動的 IMAP は `--mfa-email-address`、`--mfa-email-imap-host`、`--mfa-email-imap-port`、`--mfa-email-imap-user` で指定し、パスワードは `WSCAN_MFA_EMAIL_IMAP_PASSWORD` を推奨します。メールは一覧取得後に本文を取得し、ポーリング開始後の新着からコードを抽出します。

### Bearer 認証

通常ツール層（`scan`）で Cognito などの静的 Bearer トークンを使う場合、`--bearer` は Authorization ヘッダ指定の近道です。ブラウザ巡回と httpx の全リクエストに同じヘッダを送ります。

```bash
export WSCAN_BEARER='<token>'
python3 main.py scan https://api.example.com --bearer "$WSCAN_BEARER"
```

環境変数は `WSCAN_BEARER` を使います（`--header "Authorization: Bearer <token>"` でも指定可、`--header`/`--header-file` の Authorization を優先）。トークンはローカルへ保存されないため、毎回 CLI または環境変数で渡してください。

> ⚠️ serve の保護トークン `WSCAN_AUTH_TOKEN` は**ダッシュボード/API を守る control-plane 用**で、スキャン対象へ送る Bearer とは別物です。`--bearer` はこれを参照しません（管理トークンが検査対象へ漏れるのを防ぐため）。対象用トークンは必ず `WSCAN_BEARER` か `--bearer` で渡してください。

> ℹ️ **Hybrid/Agent モードの Bearer/カスタムヘッダ**: 対応済みです。CLI の `agent` は `--bearer`、`-H/--header`、`--header-file` を Agent ブラウザへ渡し、ダッシュボードの Agent と Hybrid Phase 1 は「認証・Cookie」の Bearer/カスタムヘッダを引き継ぎます。Hybrid Phase 2 も同じ実効ヘッダを通常スキャンへ適用します。明示した `Authorization` は Bearer 欄より優先されます。動的な `--header-refresh-cmd` は通常ツール層専用です。

### スコープ

- `target`: 巡回・攻撃してよい URL/オリジン/プレフィックス。
- `access`: ログインや外部 IdP のため到達してよいが攻撃してはいけない範囲。
- `exclude`: 削除、送信、決済、ログアウトなど避ける URL とフィールド。
- serve: `monitor.allowed_target_hosts` / `denied_target_hosts` でダッシュボード利用者が指定できるホスト自体を制限。

### TLS

PEM の cert/key は Playwright と httpx に使います。PFX/PKCS#12 は Playwright ブラウザアクセス用です。`--tls-ca-cert` と `--tls-verify` は httpx の直接リクエストでサーバ証明書を検証します。ブラウザ側は互換性維持のため HTTPS エラーを許容しながらクライアント証明書を提示します。

## 14. 高度機能

### API ファースト

```bash
python3 main.py scan https://api.example.com \
  --api-spec openapi.yaml \
  -H "Authorization: Bearer <token>" \
  --checks sqli xss mass_assignment graphql
```

OpenAPI 2.0/3.x、Swagger JSON/YAML、Postman Collection から URL、共通ヘッダ、JSON 操作を読み、フォームを辿れない API/SPA バックエンドを直接検査します。パスパラメータはサンプル値で具体化し、クエリはスキーマの既定値で補います。利用者が `-H` で渡した Authorization 等は spec の例示値より優先します。

### CMS / sitemap / SPA / JS

- `cms`: CMS の種類、バージョン、既知露出、危険な設定を確認します。
- sitemap/robots: 既定で未リンク URL のシードにします。`--no-sitemap-crawl` で無効化します。
- SPA: `--spa-crawl` で `history.pushState` フックとクリック探索を使い、React/Vue/Angular の動的ルートを収集します。
- `js_static`: インライン/外部 JavaScript の危険な source-to-sink フローを静的確認します。

### flow / 手動巡回 / HAR

- `record`: navigate、fill、click、wait 等を JSON フローへ記録します。
- `manual-crawl`: 可視ブラウザで訪問 URL、フォーム、Cookie を JSON に保存します。
- ダッシュボード手動巡回: 可視ブラウザ、CDP スクリーンキャストによる遠隔操作、URL リスト取り込みの3方式です。
- `--har`: HAR のエンドポイントと Cookie をスキャンシードへ加えます。

### ペイロード・WAF・レート制御

通常スキャンの注入系は、既定+community、LLM 不要の文脈適応 evolution、LLM 不要の mutation、LLM adaptive を加算的に使います。WAF 名を検出すると adaptive の回避ヒントへ反映します。`--max-payloads` は標準掃射を制限し、`--delay`、`--concurrency`、`--navigation-retries` で負荷と速度を調整します。

`--fast` はベストエフォートの高速プリセットです。初回の負荷確認には便利ですが、網羅性を優先する最終診断ではチェック、深さ、ペイロード上限を明示してください。

## 15. トラブルシューティング

### 対象へ接続できない

対象 URL、VPN、DNS、プロキシ、クライアント証明書、CA を確認します。社内 CA を検証する場合は `--tls-ca-cert` と `--tls-verify`、通信を観察する場合は `--proxy http://127.0.0.1:8080` を使います。

### ログイン後の画面を検査できない

`--login-success` / `--logged-in-marker`、フィールド名、Cookie の domain/path/expiry を確認します。ダッシュボードの Event Log でログインフォーム残存、MFA、`Session expired` を確認してください。

### Agent / Hybrid が開始できない

`requirements-agent.txt`、API キー、provider とモデル、Ollama の疎通を確認します。Gemini は通常スキャン・triage・remediation では使えますが、現行の Agent CLI provider 選択肢には含まれません。

### LLM が不安定

`llm.timeout_seconds` と `llm.max_retries` を調整します。通常スキャンは fallback で完了できます。adaptive の一時失敗は checkpoint に未完として残るため、同じターゲット/チェック構成で `--resume` します。

### 検出が少ない

`--checks`、Depth、Max Forms、`--max-payloads`、SPA、sitemap、手動巡回、HAR、API spec、認証スコープを確認します。`--fast` や除外指定、低すぎる時間制限が原因でないか確認してください。

### 負荷を抑えたい

Depth、Max Forms、Max Payloads、Concurrency を下げ、Delay を増やします。状態変更プローブを有効にせず、ステージングで小さいスコープから開始してください。

### 詳細ログと切り分け

`output/<timestamp>/http_requests.jsonl`、`payloads.jsonl`、`checkpoint.json`、Event Log を確認します。追加の症状別手順は [トラブルシューティング](docs/troubleshooting_ja.md) を参照してください。

## 16. 免責・ライセンス

本ツールはセキュリティ検証と教育を目的とします。許可のないシステムへの使用、対象データの破損、サービス停止、法令・契約違反につながる使用は禁止します。自動検出には誤検知と見逃しがあり、特に Agent 未確証 Finding は人手で証拠と再現性を確認してください。

本ソフトウェアは MIT License の下で提供されます。
