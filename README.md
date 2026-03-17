# WScan — Web Security Scanner

WScan は、IPA「**安全なウェブサイトの作り方**」の全脆弱性カテゴリに準拠した、Playwright ブラウザ自動化 × LLM 動的ペイロード生成による Web 脆弱性スキャナーです。

---

## IPA 準拠カバレッジ

| IPA 章番号 | 脆弱性 | チェック名 | 手法 |
|-----------|--------|-----------|------|
| 1.1 | SQLインジェクション | `sqli` | エラーベース・ブールベース・時間ベース |
| 1.2 | OSコマンドインジェクション | `os` | 出力パターン検出・時間ベース |
| 1.3 | パス名パラメータ未チェック/ディレクトリトラバーサル | `path_traversal` | ファイル内容パターン検出 |
| 1.4 | セッション管理の不備 | `session` | Cookie 属性チェック (Secure/HttpOnly/SameSite) |
| 1.5 | クロスサイト・スクリプティング | `xss` | ダイアログ確認・反射検出 |
| 1.6 | CSRF | `csrf` | POST フォームの CSRF トークン有無 |
| 1.7 | HTTPヘッダ・インジェクション | `header_injection` | CRLF 注入 → レスポンスヘッダ確認 |
| 1.8 | メールヘッダ・インジェクション | `mail_header` | メール関連フィールドへの CRLF 注入 |
| 1.9 | クリックジャッキング | `clickjacking` | X-Frame-Options / CSP frame-ancestors 確認 |
| 1.11 | アクセス制御・認可制御の欠落 | `open_redirect` | リダイレクト先未検証の検出 |
| — | SSTI (オプション) | `ssti` | テンプレートエンジン数式評価確認 |

---

## 主な機能

- **全 IPA チェックをデフォルト実行** — 引数なしで全カテゴリをスキャン
- **フィールドレベル検査** (sqli, xss, os, path_traversal, header_injection, mail_header, open_redirect) とページレベル検査 (csrf, clickjacking, session) の 2 層構造
- **BFS クローラー** — 設定可能な深さで同一ドメインリンクを自動収集
- **LLM ペイロード生成** — Claude / Ollama によるフィールド文脈を考慮した動的ペイロード
- **リアルタイム監視ダッシュボード** — WebSocket 経由でペイロード・検出結果・スクリーンショットをライブ表示
- **自己完結型 HTML レポート** — 証拠スクリーンショット・HTTP リクエスト/レスポンスつき

---

## インストール

```bash
git clone https://github.com/yourname/AutoXSScheckTool.git
cd AutoXSScheckTool

pip install -r requirements.txt
playwright install chromium
```

**動作要件**: Python 3.11+、Playwright、FastAPI、Uvicorn、httpx、Rich、anthropic (Claude 使用時)

---

## 使い方

### 基本スキャン（全 IPA チェック）

```bash
python main.py scan https://example.com
```

### チェック種類を絞る

```bash
python main.py scan https://example.com --checks xss sqli csrf clickjacking
```

### ヘッドレス + Claude LLM ペイロード生成

```bash
python main.py scan https://example.com --headless --llm claude
```

### 認証済みセッションをスキャン

```bash
# Cookie を直接渡す
python main.py scan https://example.com --cookie "session=abc123; token=xyz"

# ログインフォームを自動入力
python main.py scan https://example.com --auth-user admin --auth-pass p@ssw0rd
```

### 特定パラメーターを除外

```bash
python main.py scan https://example.com --exclude csrf_token __RequestVerificationToken
```

### CTF モード（高速スキャン + SSTI 追加）

```bash
python main.py scan https://example.com --ctf --headless --no-monitor
```

---

## コマンドラインオプション一覧

```
usage: main.py scan [オプション] URL

位置引数:
  url                    スキャン対象 URL

主要オプション:
  --checks CHECK ...     実行するチェック (デフォルト: 全 IPA チェック)
                         選択肢: sqli xss os path_traversal session csrf
                                 header_injection mail_header clickjacking
                                 open_redirect ssti
  --depth N              クロール深度 (デフォルト: 2)
  --headless             ブラウザをヘッドレスモードで起動
  --no-monitor           リアルタイム監視ダッシュボードを無効化
  --llm {ollama,claude,none}
                         LLM プロバイダー (デフォルト: ollama)
  --ollama-model MODEL   Ollama モデル名 (デフォルト: llama3)
  --payloads FILE        カスタムペイロード YAML ファイル
  --output DIR           出力ディレクトリ (デフォルト: output/<タイムスタンプ>)
  --port PORT            監視ダッシュボードポート (デフォルト: 8765)
  --timeout SECS         リクエストタイムアウト秒数 (デフォルト: 30)
  --max-forms N          1 ページあたり最大フォーム数 (デフォルト: 50)
  --exclude PARAM ...    スキップするパラメーター名
  --exclude-file FILE    除外パラメーター一覧ファイル
  --ctf                  CTF モード: SSTI 追加・遅延半減
  --cookie COOKIES       スキャン前にセットする Cookie 文字列
  --auth-user USER       ログインフォーム自動入力ユーザー名
  --auth-pass PASS       ログインフォーム自動入力パスワード
```

---

## 出力ファイル

```
output/
└── 20240101_120000/
    ├── report.html       # 自己完結型 HTML レポート（ブラウザで開く）
    ├── evidence.json     # 全検出結果 JSON
    └── screenshots/      # スキャン中スクリーンショット
```

### 深刻度

| 深刻度 | 主な例 |
|--------|-------|
| **Critical** | JS ダイアログが発火した XSS・SSTI・SQLi エラー |
| **High** | 反射 XSS・ブールベース SQLi・ディレクトリトラバーサル成功・ヘッダインジェクション |
| **Medium** | CSRF トークン欠如・クリックジャッキング・セッション Cookie 属性不備・オープンリダイレクト |
| **Low/Info** | その他軽微な設定ミス |

---

## カスタムペイロード

`config/default_payloads.yaml` をコピーして編集し、`--payloads` で指定します。

```yaml
xss:
  - "<script>alert('custom')</script>"

path_traversal:
  - "../../../../etc/shadow"
```

---

## 検知ロジック詳細

### XSS (IPA 1.5)
1. **ダイアログ確認 (Critical)**: `alert()` ダイアログ発火
2. **反射確認 (High)**: レスポンス HTML 内の未エンコードマーカーを検出
   - HTML コメント内の出現を除外、エンコード済み (`&lt;`) のみの出現も除外

### SQLi (IPA 1.1)
1. **エラーベース (Critical)**: DB エラーメッセージのパターン照合
2. **ブールベース (High)**: 真条件 vs 偽条件のレスポンス長差異で判定
3. **時間ベース (High)**: `SLEEP(3)` 投入後 ≥2.5 秒の遅延

### ディレクトリトラバーサル (IPA 1.3)
- `/etc/passwd`・`win.ini` 等の典型ファイル内容を正規表現でマッチ

### セッション管理 (IPA 1.4)
- ブラウザ Cookie を検査: Secure / HttpOnly / SameSite 各フラグの有無をチェック

### CSRF (IPA 1.6)
- POST フォームに CSRF トークンフィールドが存在しない場合に報告

### HTTP ヘッダインジェクション (IPA 1.7)
- CRLF エンコードバリアントを注入し、レスポンスヘッダに `X-WscanHdrInject` が出現すれば確定

### メールヘッダインジェクション (IPA 1.8)
- `email`/`to`/`subject` 等のフィールドに CRLF 注入し、エラーメッセージまたは未エンコード反射を検出

### クリックジャッキング (IPA 1.9)
- `X-Frame-Options: DENY/SAMEORIGIN` または CSP `frame-ancestors` が欠如している場合に報告

### オープンリダイレクト (IPA 1.11)
- `next`/`redirect`/`url` 等のリダイレクト系パラメーターに外部 URL を注入し、実際のリダイレクトを確認

### SSTI (オプション)
- ベースライン取得後、数式 (`{{7*7}}` → `49`) が新たに出現した場合のみ報告

---

## アーキテクチャ

```
main.py / launcher.py
    └── ScanEngine (wscan/engine.py)
            ├── BrowserManager (wscan/browser.py)      # Playwright 操作
            ├── PayloadGenerator (wscan/payload_gen.py) # LLM / デフォルト
            ├── MonitorServer (wscan/monitor.py)        # WebSocket ダッシュボード
            └── Scanners (wscan/scanners/)
                    ├── XSSScanner            (IPA 1.5)
                    ├── SQLiScanner           (IPA 1.1)
                    ├── OSInjectionScanner    (IPA 1.2)
                    ├── PathTraversalScanner  (IPA 1.3)
                    ├── SessionScanner        (IPA 1.4) ← ページレベル
                    ├── CSRFScanner           (IPA 1.6) ← ページレベル
                    ├── HeaderInjectionScanner(IPA 1.7)
                    ├── MailHeaderInjectionScanner (IPA 1.8)
                    ├── ClickjackingScanner   (IPA 1.9) ← ページレベル
                    ├── OpenRedirectScanner   (IPA 1.11)
                    └── SSTIScanner           (オプション)
```

---

## 注意事項 / 免責事項

> **本ツールは、自分が管理するシステムまたは明示的なテスト許可を得たシステムに対してのみ使用してください。**
> 許可なく第三者のシステムをスキャンすることは、不正アクセス禁止法などの法律に違反する可能性があります。
> 開発者は本ツールの不正使用に対して一切の責任を負いません。

---

## ライセンス

MIT License
