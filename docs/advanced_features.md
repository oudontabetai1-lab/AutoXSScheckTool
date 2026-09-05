# 高度診断支援機能 — 詳細調査レポート

元々 `b1d1128` で実装された A〜J の 10 機能に加え、K〜P の 6 機能を追加実装。合計 16 機能。

---

## 概要

| ID | 機能名 | 実装ファイル | 状態 |
|----|--------|-------------|------|
| A | 重複ページスキップ | `wscan/engine.py` | 実装済み |
| B | ビジュアルサイトマップ | `wscan/report.py` | 実装済み |
| C | CMS検出 | `wscan/cms_detect.py`, `wscan/scanners/cms.py` | 実装済み |
| D | CI/CD REST API | `wscan/monitor.py` | 実装済み |
| E | 信頼度スコア | `wscan/scanners/base.py` | 実装済み |
| F | マルチテンプレートレポート | `wscan/report.py` | 実装済み |
| G | コンプライアンスマッピング | `wscan/compliance_map.py` | 実装済み |
| H | フロー記録・再生 | `wscan/flow_recorder.py`, `main.py` | 実装済み |
| I | 差分スキャン | `wscan/diff_scan.py`, `wscan/engine.py` | 実装済み |
| J | LLMリメディエーション提案 | `wscan/remediation.py` | 実装済み |
| K | SARIF 2.1.0 出力 | `wscan/sarif.py`, `wscan/engine.py` | 実装済み |
| L | Webhook/Slack 通知 | `wscan/notification.py`, `wscan/engine.py` | 実装済み |
| M | マルチターゲット一括スキャン | `wscan/batch_runner.py`, `main.py` | 実装済み |
| N | リクエストレート制御 | `wscan/engine.py`, `main.py` | 実装済み |
| O | HAR ファイルインポート | `wscan/har_importer.py`, `wscan/engine.py` | 実装済み |
| P | WebSocket インジェクション | `wscan/scanners/websocket.py` | 実装済み |

---

## A. 重複ページスキップ

**ファイル**: `wscan/engine.py:565-572`, `engine.py:598,651-666`

### 実装方式

クロール時に各ページのHTML構造フィンガープリントを計算し、類似ページを除外する。

```python
@staticmethod
def _page_fingerprint(html: str) -> str:
    tags = re.findall(r'<\w+', html.lower())
    return hashlib.md5(''.join(tags[:50]).encode()).hexdigest()[:12]
```

- HTML の先頭50個のタグ名を抽出（テキスト・属性値は無視）
- MD5 ハッシュの先頭12文字をフィンガープリントとして使用
- `_seen_page_fingerprints` セットで既出フィンガープリントを追跡
- 同一フィンガープリントのページはスキャンをスキップ

### 効果

- 一覧ページや商品ページなど、同一テンプレートを使う大量のページを1回だけスキャン
- スキャン時間の大幅削減・ノイズ低減

### 注意点

- 先頭50タグのみ使用するため、フッターのみ異なるページは同一と判定される可能性がある
- テンプレート構造が大きく変わるサイトでは誤スキップが発生しにくい

---

## B. ビジュアルサイトマップ

**ファイル**: `wscan/report.py`（`audit` テンプレート内）

### 実装方式

D3.js の力指向グラフ（Force-Directed Graph）でページ間のリンク関係を可視化。

- ノード: クロールした各 URL
- エッジ: ページ間のハイパーリンク
- 脆弱性が検出されたノードは赤色で表示
- JavaScript が無効な環境向けに `<ul>` ツリー形式のフォールバックも提供

### 確認方法

`audit` レポート（`report.html`）の「Site Map」セクションに表示される。

---

## C. CMS検出

**ファイル**: `wscan/cms_detect.py`, `wscan/scanners/cms.py`

### 対応 CMS

WordPress, Drupal, Django, Laravel, EC-CUBE, Joomla, Magento

### 検出シグナル

| CMS | 主な検出方法 |
|-----|------------|
| WordPress | `wp-content/`, `wp-includes/` パス、generator メタタグ、`X-Powered-By` ヘッダ |
| Drupal | `sites/default/`, `Drupal.settings`, `X-Generator: Drupal` |
| Django | `csrfmiddlewaretoken`、Django エラーページ特徴 |
| Laravel | `laravel_session` Cookie、`X-Powered-By: PHP/Laravel` |
| EC-CUBE | EC-CUBE 固有パス・Cookie |
| Joomla | `/components/`, `/modules/`, generator メタタグ |
| Magento | `Mage.Cookies`, `/skin/frontend/`, `X-Magento-*` ヘッダ |

### 信頼度レベル

`CmsInfo.confidence`: `"high"` / `"medium"` / `"low"`

### CMS 固有チェック

`wscan/scanners/cms.py` で CMS 判定後に固有の追加チェックを実施。

---

## D. CI/CD REST API

**ファイル**: `wscan/monitor.py:129-207`

### エンドポイント一覧

| メソッド | パス | 説明 |
|---------|------|------|
| `POST` | `/api/v1/scan` | スキャンを非同期起動 |
| `GET` | `/api/v1/scan/status` | スキャン進捗ステータス取得 |
| `GET` | `/api/v1/scan/findings` | 検出済み脆弱性リスト取得 |
| `GET` | `/api/v1/scan/report` | HTML レポートのパスを返す |
| `GET` | `/api/v1/scan/results` | 全結果サマリー（status + findings）を取得 |

### 利用例（CI パイプライン）

```bash
# 1. スキャン開始
curl -X POST http://localhost:8765/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://target.example.com", "depth": 3}'

# 2. ステータス確認
curl http://localhost:8765/api/v1/scan/status

# 3. 結果取得
curl http://localhost:8765/api/v1/scan/findings
```

---

## E. 信頼度スコア

**ファイル**: `wscan/scanners/base.py:90`, `base.py:224-247`

### スコア定義

| 値 | 意味 |
|----|------|
| `"confirmed"` | JS アラートが実際に発火した、または二重検証が成功した確実な脆弱性 |
| `"likely"` | 強い証拠があるが完全検証はできていない脆弱性 |
| `"tentative"` | ヒューリスティック判定または検証が取れなかった脆弱性 |

### 自動割り当てロジック

```python
if dialog_confirmed:
    confidence = "confirmed"
elif verified and strong_evidence:
    confidence = "likely"
else:
    confidence = "tentative"
```

`Finding.to_dict()` の出力に `confidence` フィールドが含まれ、レポートおよび REST API レスポンスに反映される。

---

## F. マルチテンプレートレポート

**ファイル**: `wscan/report.py:50-72`

### テンプレート種別

| テンプレート | ファイル名 | 対象読者 | 内容 |
|------------|----------|---------|------|
| `audit` (デフォルト) | `report.html` | セキュリティ担当・審査担当 | 全詳細情報（リクエスト/レスポンス、スクリーンショット、サイトマップ） |
| `executive` | `report_executive.html` | 経営層・管理職 | 重要度別サマリー、グラフ、対応優先度 |
| `developer` | `report_developer.html` | 開発者 | 脆弱性詳細、コード例入り修正ガイダンス |

### 使い方

```bash
# audit レポート（デフォルト）
python main.py scan --template audit https://target.example.com

# 経営向け
python main.py scan --template executive https://target.example.com

# 開発者向け
python main.py scan --template developer https://target.example.com
```

---

## G. コンプライアンスマッピング

**ファイル**: `wscan/compliance_map.py`

### マッピング対象規格

| 規格 | バージョン |
|------|----------|
| PCI DSS | v4.0 |
| OWASP ASVS | 4.0 |
| OWASP Top 10 | 2021 |
| IPA | 安全なウェブサイトの作り方 |

### 対応脆弱性タイプ

`sqli`, `sqli_auth_bypass`, `xss`, `dom_xss`, `stored_xss`, `os`, `ssti`, `path_traversal`, `open_redirect`, `csrf`, `cors`, `header_injection`, `mail_header`, `clickjacking`, `session`, `ssrf`, `deserialization`, `request_smuggling`, `host_header`, `graphql`, `jwt`

### 利用例

```python
from wscan.compliance_map import get_refs
refs = get_refs("xss")
# {
#   "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
#   "owasp_asvs":  ["ASVS V5.3.3"],
#   "owasp_top10": ["A03:2021 Injection"],
#   "ipa":         ["IPA 1.5 クロスサイト・スクリプティング"]
# }
```

`Finding.to_dict()` に `compliance_refs` フィールドとして自動付与される。

---

## H. フロー記録・再生

**ファイル**: `wscan/flow_recorder.py`, `main.py:576-586`, `main.py:1306-1322`

### 概要

Playwright を使って手動操作（ナビゲーション・フォーム入力・クリック）を JSON 形式で記録し、スキャン時に再生してペイロードを注入する。認証フローなど通常クロールでは到達できない画面のスキャンに使用。

### ステップ形式

```json
[
  {"action": "navigate", "url": "http://example.com/login"},
  {"action": "fill",     "selector": "#username", "value": "admin"},
  {"action": "fill",     "selector": "#password", "value": "secret"},
  {"action": "click",    "selector": "button[type=submit]"},
  {"action": "navigate", "url": "http://example.com/profile"},
  {"action": "fill_inject", "selector": "#bio", "field_name": "bio"}
]
```

`fill_inject` ステップがペイロード注入ポイント。

### 記録コマンド

```bash
python main.py record --output flows/login.json http://example.com/login
# 操作後 Ctrl+C で JSON 保存
```

### セキュリティ考慮

記録時の JavaScript フック関数名にランダムトークンを使用 (`__wscan_fill_{token}__`) し、悪意あるページ JS によるステップ改ざんを防止。

### ビジュアル シナリオ ビルダー（ダッシュボード）

**ファイル**: `templates/dashboard.html`, `wscan/monitor.py`, `wscan/engine.py`

手動で攻撃シナリオ（`ScanFlow`）を組む作業を視覚的に行えるビルダーを搭載。各ステップ
（🌐移動 / ⌨️入力 / 📤送信 / 🖱️クリック / ⏱️待機）をタイムライン状のカードとして並べ替え・
複製・削除でき、上部には流れを示す横型フローチャートのプレビューを表示する。

利用箇所は 2 つ:

1. **設定 → 「攻撃シナリオ」タブ**: スキャン開始前にシナリオを作成。保存したシナリオは
   スキャン設定とともに送信される。
2. **巡回レビュー（任意）**: `interactive_crawl_review` を有効にすると、巡回完了後に
   検査を一時停止し、ダッシュボード中央の**画面遷移図（巡回マップ）**でサイト構造を確認
   してから検査を開始できる。遷移図の上部に出るバーから「✅ 検査開始 / 🔁 再巡回・URL追加・
   シナリオ / ⏹ 中止」を選ぶ。補完が必要なときだけ「再巡回…」を開くと、発見した画面・
   フォーム・入力欄の一覧（パレット）を見ながら追加URL・手動巡回JSON・手動シナリオを足せる。
   作成したシナリオは「検査開始」時に取り込まれ、検査前に実行される。
   ※「検査開始」を押すと必ず次フェーズへ進む（再巡回はバー/詳細パネルから明示的に選んだ
   ときだけ）。以前は追加URL欄や手動巡回ファイルの自動補完が残っていると、検査開始後も
   レビューが繰り返し出てしまう不具合があった。

ビルダーが生成するシナリオは既存の `ScanFlow` 形式（`navigate` / `fill` / `submit` /
`click` / `wait`）でそのまま `FlowRunner` が実行する。シナリオの最後の `navigate` 先の
URL が、そのシナリオの攻撃対象ページになる。

---

## I. 差分スキャン

**ファイル**: `wscan/diff_scan.py`, `wscan/engine.py`

### 概要

前回スキャンの `evidence.json` と今回の結果を比較し、新規・修正済み・継続の3種類に分類する。

### 分類定義

| カテゴリ | 意味 |
|---------|------|
| `new_findings` | 今回のスキャンで初めて検出された脆弱性 |
| `fixed_findings` | 前回検出されたが今回は検出されなかった（修正済みとみなす） |
| `persistent_findings` | 前回・今回ともに検出された継続する脆弱性 |

### キー設計

`(url, field_name, check_type)` の正規化タプルで同一性を判定（URLの末尾スラッシュは正規化）。

### 使い方

```bash
# --diff-scan で前回出力ディレクトリを指定
python main.py scan --diff-scan ./output_2026-04-01 https://target.example.com
```

### 出力例

```
差分サマリー: 新規 3 件 / 修正済み 1 件 / 継続 5 件
```

---

## J. LLMリメディエーション提案

**ファイル**: `wscan/remediation.py`

### 概要

検出された脆弱性に対して、LLM（Claude/OpenAI/Gemini/Ollama）を使って文脈に応じた修正ガイダンスを生成する。LLM が利用不可の場合は静的テンプレートにフォールバックする。

### 静的テンプレート対応脆弱性

`sqli`, `xss`, `dom_xss`, `stored_xss`, `os`, `ssti`, `path_traversal`, `open_redirect`, `csrf`, `cors`, `clickjacking`, `ssrf`, `session`, `header_injection`, `mail_header`, `deserialization`, `request_smuggling`, `host_header`

### LLMプロンプト構造

1. 脆弱性タイプ・URL・フィールド名・ペイロード・証拠を渡す
2. 使用言語/フレームワークをコンテキストとして推定
3. 具体的なコード修正例を含む日本語ガイダンスを生成

### 使い方

```python
from wscan.remediation import generate_fix
fix_text = await generate_fix(finding, engine.payload_gen)
```

`developer` テンプレートレポートでは各 Finding に修正ガイダンスが自動付与される。

---

---

## K. SARIF 2.1.0 出力

**ファイル**: `wscan/sarif.py`, `wscan/engine.py:_save_evidence()`

### 目的
GitHub Advanced Security / VS Code / Azure DevOps 等の CI ツールにネイティブ統合できる標準フォーマット (SARIF 2.1.0) でスキャン結果を出力する。

### 実装

- `SarifExporter.export()` が `findings_dicts` リストから SARIF 2.1.0 JSON を生成
- `write_sarif()` が `Finding` オブジェクトまたは dict を受け取り `report.sarif` に書き出す
- `_save_evidence()` の末尾で自動出力（`--no-sarif` で無効化可能）

### SARIF マッピング

| Finding フィールド | SARIF フィールド |
|-------------------|----------------|
| `check_type` | `ruleId` + `tool.driver.rules[].id` |
| `severity` (critical/high) | `level: error` |
| `severity` (medium) | `level: warning` |
| `verified=false` | 重大度にかかわらず `level: note` |
| `url` | `locations[0].physicalLocation.artifactLocation.uri` |
| `evidence` + `field_name` + `payload` | `message.text` |
| `cvss_score`, `confidence`, `compliance_refs` | `properties` |

通常層（確実性重視）では `verified=true` の Finding だけを確証 (confirmed) 件数として扱います。未確証 (hypothesis) も SARIF result から削除せず、`verification_state` を保持したまま `level: note` に下げるため、CI ゲートと人手レビューを分離できます。

`run.properties.coverage` に検査カバレッジ補助情報を出します（0016）: `check_coverage`（registry 全数・選択された check・未選択 check・COMPLETE/PARTIAL/INCOMPLETE・設定の誤記）と、前提不足で実質検査できなかった check（`prerequisite_missing`）・state profile で送信 skip された check（`state_profile_skipped`）。SARIF 消費側（CI/ダッシュボード）が「results が 0＝安全ではなく、未実行や前提不足の検査がある」を機械的に判別できます。

### 使い方

```bash
# デフォルト有効 (output/<timestamp>/report.sarif に自動出力)
python main.py scan https://target.example.com

# 無効化
python main.py scan --no-sarif https://target.example.com
```

---

## L. Webhook / Slack 通知

**ファイル**: `wscan/notification.py`, `wscan/engine.py:_record_finding()`

### 目的
重大な脆弱性検出時にリアルタイムで Slack / 汎用 Webhook に通知し、CI/CD でのアラートを即時に促す。

### 実装

- `NotificationManager.notify_finding()` — `verified=true` かつ重大度閾値以上の Finding のみ通知（重複防止あり）
- `NotificationManager.notify_scan_complete()` — スキャン完了サマリー通知
- `_record_finding()` に `asyncio.ensure_future()` でフックを注入（スキャン処理をブロックしない）
- Slack Block Kit 形式 + 汎用 JSON の両対応

未確証 (hypothesis) はレポートと SARIF に残りますが、Finding 通知は送信しません。

### 使い方

```bash
# Slack Incoming Webhook
python main.py scan --notify-webhook https://hooks.slack.com/... https://target.example.com

# 通知閾値を medium に下げる
python main.py scan --notify-webhook URL --notify-severity medium https://target.example.com
```

---

## M. マルチターゲット一括スキャン

**ファイル**: `wscan/batch_runner.py`, `main.py` (`batch` サブコマンド)

### 目的
複数の URL を 1 コマンドで順次スキャンし、統合サマリー (`batch_summary.json`) を生成する。

### バッチ定義 YAML フォーマット

```yaml
global:
  depth: 2
  checks: [sqli, xss, os]
  headless: true

targets:
  - url: https://app1.example.com
    label: "App1 Production"
    auth_user: admin
    auth_pass: secret
  - url: https://app2.example.com
    label: "App2 Staging"
    depth: 3
```

### 使い方

```bash
python main.py batch targets.yaml
python main.py batch targets.yaml --output ./batch_results
```

### 出力

- `output/batch_<timestamp>/<sanitized_host>/` に各ターゲットの結果
- `output/batch_<timestamp>/batch_summary.json` に統合サマリー

---

## N. リクエストレート制御

**ファイル**: `wscan/engine.py`, `main.py`, `config/wscan.yaml`

### 目的
リクエスト間隔を `--delay` で任意に設定し、本番環境への負荷を制御する。

### 実装

`_effective_delay = request_delay * sleep_factor` として全 `asyncio.sleep()` 呼び出しを統一。

| モード | sleep_factor | delay=0.5 の場合 |
|--------|-------------|----------------|
| 通常   | 1.0 | 0.5 秒 |
| CTF    | 0.5 | 0.25 秒 |
| Fast   | 0.0 | 0 秒（強制上書き） |

### 使い方

```bash
# 2秒間隔でスキャン
python main.py scan --delay 2.0 https://target.example.com

# 制限なし (fast と同等)
python main.py scan --delay 0 https://target.example.com
```

---

## O. HAR ファイルインポート

**ファイル**: `wscan/har_importer.py`, `wscan/engine.py:_phase_crawl()`

### 目的
ブラウザの DevTools や Burp Suite でキャプチャした HAR ファイルからエンドポイント・Cookie・ヘッダをスキャンのシードとして読み込む。

### 抽出内容

| HAR フィールド | 用途 |
|---------------|------|
| `request.url` | BFS クロールキューに追加 |
| `response.headers[Set-Cookie]` | Playwright Cookie として設定 |
| `request.headers[Cookie]` | Playwright Cookie として設定 |
| `request.headers[Authorization]` | `HarSeedData.headers` に保持 |

### 使い方

```bash
# DevTools でキャプチャした HAR をシードに使用
python main.py scan --har captured.har https://target.example.com
```

---

## P. WebSocket インジェクションスキャナー

**ファイル**: `wscan/scanners/websocket.py`, `wscan/scanners/__init__.py`

### 目的
Playwright の WebSocket イベントフックを使い、WS エンドポイントへのメッセージにペイロードを注入してインジェクション脆弱性を検査する。

### 検査パターン

| check_type | ペイロード例 | 検出方法 |
|------------|------------|---------|
| `xss` | `<script>alert('wsxss')</script>` | レスポンスにタグが反射 |
| `sqli` | `' OR '1'='1` | SQL エラーメッセージ |
| `os` | `; echo wsostest123;` | エコー結果 |
| `ssti` | `{{7*7}}` | `49` の計算結果 |

### 動作フロー

1. `scan_page()` でページをナビゲートし WS 接続を観測
2. 接続された WS メッセージの JSON 構造を推定
3. 各フィールドにペイロードを注入した WS メッセージを送信
4. レスポンスをパターンマッチで検査

### 使い方

```bash
# WebSocket スキャンを有効化
python main.py scan --checks websocket https://target.example.com

# 他のチェックと組み合わせ
python main.py scan --checks xss sqli websocket https://target.example.com
```

---

## 実装品質評価

| 機能 | 完成度 | 備考 |
|------|--------|------|
| A 重複ページスキップ | ★★★★☆ | フィンガープリントが先頭50タグのみで粗い |
| B ビジュアルサイトマップ | ★★★★☆ | D3.js + フォールバックで堅牢 |
| C CMS検出 | ★★★★★ | 7 CMS 対応、バージョン検出あり |
| D CI/CD REST API | ★★★★☆ | 認証なし（本番利用時は要追加） |
| E 信頼度スコア | ★★★★★ | dialog_confirmed と verified の組み合わせで精度良好 |
| F マルチテンプレート | ★★★★☆ | 3テンプレート対応 |
| G コンプライアンスマッピング | ★★★★★ | 4規格・20+脆弱性タイプ対応 |
| H フロー記録・再生 | ★★★★☆ | セキュアなトークン実装あり |
| I 差分スキャン | ★★★★☆ | キー設計がシンプルで信頼性高い |
| J LLMリメディエーション | ★★★★☆ | 静的フォールバック充実 |
| K SARIF 出力 | ★★★★★ | SARIF 2.1.0 完全準拠、remediation テキスト自動付与 |
| L Webhook/Slack 通知 | ★★★★☆ | Block Kit 対応、fire-and-forget で非ブロッキング |
| M マルチターゲット一括スキャン | ★★★★☆ | YAML定義、JSON サマリー生成 |
| N リクエストレート制御 | ★★★★★ | sleep_factor との統合がクリーン |
| O HAR インポート | ★★★★☆ | Set-Cookie/Authorization 自動抽出 |
| P WebSocket スキャナー | ★★★☆☆ | JSON フィールド注入対応、WS 切断時は不安定の可能性 |
