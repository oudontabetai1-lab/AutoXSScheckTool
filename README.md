# WScan — Web Security Scanner

WScan は、Playwright ブラウザ自動化と LLM による動的ペイロード生成を組み合わせた、自動 Web 脆弱性スキャナーです。

---

## 主な機能

| 機能 | 説明 |
|------|------|
| **XSS 検知** | DOM ダイアログ確認 + レスポンス内の未エンコード反射を検出 |
| **SQL インジェクション検知** | エラーベース・ブールベース・時間ベースの 3 層検出 |
| **OS コマンドインジェクション検知** | コマンド出力パターン照合 + 時間ベース盲目的検出 |
| **SSTI 検知** | 数式プローブ + ベースライン比較による誤検知抑制 |
| **BFS クローラー** | 設定可能な深さでリンクを自動収集 |
| **LLM ペイロード生成** | Claude / Ollama によるフィールド文脈を考慮したペイロード生成 |
| **リアルタイム監視** | WebSocket ベースのダッシュボード（スクリーンショット・ネットワークログ付き） |
| **HTML レポート** | 証拠付きの自己完結型セキュリティレポートを出力 |

---

## インストール

```bash
# リポジトリをクローン
git clone https://github.com/yourname/AutoXSScheckTool.git
cd AutoXSScheckTool

# 依存関係をインストール
pip install -r requirements.txt

# Playwright ブラウザをインストール
playwright install chromium
```

### 依存関係

- Python 3.11+
- Playwright (chromium)
- FastAPI + Uvicorn (監視ダッシュボード)
- httpx
- Rich (ターミナル出力)
- anthropic (Claude LLM 使用時)

---

## 使い方

### 基本スキャン

```bash
python main.py scan https://example.com
```

### ヘッドレスモードで XSS と SQLi を検査

```bash
python main.py scan https://example.com --checks xss sqli --headless
```

### クロール深度・LLM・出力ディレクトリを指定

```bash
python main.py scan https://example.com \
  --depth 3 \
  --llm claude \
  --output ./results
```

### 認証済みセッションをスキャン

```bash
# Cookie を直接渡す
python main.py scan https://example.com --cookie "session=abc123; token=xyz"

# フォーム自動入力でログイン
python main.py scan https://example.com --auth-user admin --auth-pass password
```

### 特定のパラメーターを除外

```bash
python main.py scan https://example.com --exclude csrf_token __RequestVerificationToken
```

### CTF モード（高速スキャン）

```bash
python main.py scan https://example.com --ctf --headless
```

---

## コマンドラインオプション一覧

```
usage: main.py scan [オプション] URL

位置引数:
  url                   スキャン対象の URL

オプション:
  --payloads FILE       カスタムペイロード YAML ファイル
  --checks CHECK ...    実行するチェック: sqli xss os ssti (デフォルト: sqli xss os)
  --depth N             クロール深度 (デフォルト: 2)
  --headless            ブラウザをヘッドレスモードで起動
  --no-monitor          リアルタイム監視ダッシュボードを無効化
  --llm {ollama,claude,none}
                        LLM プロバイダー (デフォルト: ollama)
  --ollama-model MODEL  Ollama モデル名 (デフォルト: llama3)
  --output DIR          出力ディレクトリ (デフォルト: output/<タイムスタンプ>)
  --port PORT           監視ダッシュボードのポート (デフォルト: 8765)
  --timeout SECS        リクエストタイムアウト秒数 (デフォルト: 30)
  --max-forms N         1 ページあたりの最大フォーム数 (デフォルト: 50)
  --exclude PARAM ...   スキップするパラメーター名
  --exclude-file FILE   除外パラメーターを記述したテキストファイル
  --ctf                 CTF モード: SSTI を追加し遅延を半減
  --cookie COOKIES      スキャン前にセットする Cookie 文字列
  --auth-user USER      ログインフォーム自動入力用ユーザー名
  --auth-pass PASS      ログインフォーム自動入力用パスワード
```

---

## 出力

スキャン終了後、指定した出力ディレクトリ（デフォルト: `output/<タイムスタンプ>/`）に以下のファイルが生成されます。

```
output/
└── 20240101_120000/
    ├── report.html       # 自己完結型 HTML レポート（ブラウザで開く）
    ├── evidence.json     # 全検出結果の JSON（ツール連携用）
    └── screenshots/      # スキャン中に撮影したスクリーンショット
```

### レポートの見方

- **Critical**: JavaScript ダイアログが確認された XSS・SQLi・SSTI
- **High**: ペイロードの反射確認 / ブールベース SQLi / 時間ベース OS インジェクション
- 各検出結果にはペイロード・フィールド名・URL・ネットワークリクエスト/レスポンスが記録されます

---

## カスタムペイロード

`config/default_payloads.yaml` をコピーして編集し、`--payloads` で指定します。

```yaml
xss:
  - "<script>alert('custom')</script>"
  - "<img src=x onerror=alert(1)>"

sqli:
  - "' OR 1=1--"
  - "1' AND SLEEP(5)--"
```

---

## 検知ロジックの詳細

### XSS スキャナー

1. **ダイアログ確認 (Critical)**: ペイロード投入後に `alert()` ダイアログが発火した場合
2. **反射確認 (High)**: レスポンス HTML 内に未エンコードのマーカーが出現した場合
   - HTML コメント内 (`<!-- ... -->`) の出現は除外
   - HTML エンコードされた形 (`&lt;script&gt;`) のみの出現は除外

### SQL インジェクションスキャナー

1. **エラーベース (Critical)**: レスポンスに DB エラーメッセージが含まれる場合
2. **ブールベース (High)**: 真条件レスポンス ≈ ベースライン かつ 偽条件レスポンスが大きく乖離する場合
3. **時間ベース (High)**: 時間ベースペイロード投入後にレスポンスが 2.5 秒以上遅延する場合

### SSTI スキャナー

- ベースラインレスポンスを取得し、ペイロード投入後に数式結果 (`49`, `7777777` など) が**新たに**出現した場合のみ検出（既存の数値による誤検知を防止）

### OS インジェクションスキャナー

1. **出力確認 (Critical)**: `uid=`, `root:x:`, `Windows IP Configuration` などの典型的な出力パターン
2. **時間ベース (High)**: `sleep 3` / `ping -c 3` 投入後の遅延確認

---

## アーキテクチャ

```
main.py / launcher.py
    └── ScanEngine (wscan/engine.py)
            ├── BrowserManager (wscan/browser.py)   # Playwright 操作
            ├── PayloadGenerator (wscan/payload_gen.py)  # LLM / デフォルト
            ├── MonitorServer (wscan/monitor.py)     # WebSocket ダッシュボード
            └── Scanners (wscan/scanners/)
                    ├── XSSScanner
                    ├── SQLiScanner
                    ├── OSInjectionScanner
                    └── SSTIScanner
```

---

## 注意事項 / 免責事項

> **本ツールは、自分が管理するシステムまたは明示的なテスト許可を得たシステムに対してのみ使用してください。**
> 許可なく第三者のシステムをスキャンすることは、不正アクセス禁止法などの法律に違反する可能性があります。
> 開発者は、本ツールの不正使用に対して一切の責任を負いません。

---

## ライセンス

MIT License
