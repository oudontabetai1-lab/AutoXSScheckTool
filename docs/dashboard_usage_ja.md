# WScan ダッシュボード利用ガイド

このガイドでは、WScan の Server Portal から設定画面を開き、通常・Agent・Hybrid の各モードで検査を開始し、実行状況と結果を確認する手順を説明します。

ダッシュボード（`python3 main.py serve`）が WScan の基本の操作面です。検査の起動、機能フラグの切り替え、進捗確認、結果閲覧までここで完結します（CLI は自動化・CI 向けの補助入口）。

スクリーンショットはローカルの疑似脆弱アプリに対する実行例です。実際の画面では対象や検出内容が異なります。

> WScan は脆弱性検査ツールです。自分が管理している環境、または検査許可を得た環境だけを対象にしてください。最初はステージング環境と小さいスコープで負荷・副作用を確認してください。

## 1. 3モードを選ぶ

WScan は、モードごとに優先する品質が異なります。

| モード | 画面の入口 | 優先するもの | 結果の読み方 |
| --- | --- | --- | --- |
| 通常 | 設定画面下部の「スキャン開始」 | 確実性 | 決定論スキャナの Finding。`verified`、`confidence`、Evidence を確認 |
| Agent | 「Agent Browser」タブ | 独自性 | LLM の独自解釈。HTML レポートで `🤖 Agent発見` バッジを確認 |
| Hybrid | 「ハイブリッド」タブ | 確実性と独自性の中間 | 通常 Finding と Agent Finding を出自ラベル付きで併記 |

通常モードは定期診断や再検査、Agent は複雑な導線の探索、Hybrid は SPA や認証後画面を広く探しながら決定論スキャンも実施したい場合に向いています。

## 2. 事前準備

本体と Playwright Chromium をインストールします。

```bash
git clone https://github.com/oudontabetai1-lab/AutoXSScheckTool.git
cd AutoXSScheckTool
python3 -m pip install -r requirements.txt
playwright install chromium
```

Agent または Hybrid を使う場合は追加依存を入れます。

```bash
python3 -m pip install -r requirements-agent.txt
```

利用する LLM に合わせて API キーまたは Ollama を準備します。ダッシュボードの Agent/Hybrid タブで選択できる provider は Claude、OpenAI、Ollama です。

```bash
# Claude の例
export ANTHROPIC_API_KEY="<api-key>"
```

Python 3.11 以上を推奨します。

## 3. ダッシュボードを起動する

ローカル限定で起動する例:

```bash
python3 main.py serve --host 127.0.0.1 --port 8765
```

ブラウザで次を開きます。

```text
http://localhost:8765/
```

`/` はスキャン履歴、現在の実行、定期スキャンを扱う Server Portal です。「新規スキャン」を押すと `/monitor` の設定画面へ移動します。直接 `http://localhost:8765/monitor` を開いても構いません。

イントラネットから利用する場合は、認証トークンを設定してください。

```bash
export WSCAN_AUTH_TOKEN="<long-random-token>"
python3 main.py serve --host 0.0.0.0 --port 8765
```

ポートが使用中なら `--port 8766` のように変更します。

## 4. 初期設定画面を確認する

![ダッシュボード初期設定画面](images/dashboard-start.png)

画面上部には Target URL、スキャンプロファイル、設定タブがあります。通常スキャンを始める前に、少なくとも次を確認します。

1. Target URL が許可済みの検査対象である。
2. 削除、決済、送信、ログアウトなど副作用のある URL を除外した。
3. 認証や外部 IdP の範囲を「攻撃対象」と「アクセスのみ許可」に分けた。
4. リクエスト間隔と並列数が対象の許容負荷に収まる。

## 5. 通常スキャンの設定を入力する

Target URL を入力し、目的に近いプロファイルを選びます。

| プロファイル | 用途 |
| --- | --- |
| 高速トリアージ | 深さ1・少数ペイロードで XSS/SQLi/OS を短時間確認 |
| 標準Web診断 | IPA 主要カテゴリを中心に巡回・検査 |
| 認証あり診断 | ログイン後画面、権限昇格、IDOR を重視 |
| 精度重視診断 | 深い巡回、DOM/Stored XSS、JWT/GraphQL、証跡を重視 |
| CTF/演習 | SSTI、OS、SSRF、Flag 探索を重視 |

![検査設定の入力例](images/dashboard-configured.png)

### 基本設定

| 項目 | 内容 | 初回の目安 |
| --- | --- | --- |
| クロール深度 | 同一スコープ内を辿る深さ | `1` から開始 |
| タイムアウト | リクエスト/ページ待機秒 | 既定 `30` |
| 最大フォーム数/ページ | 1ページで検査するフォーム数 | 既定 `50`。対象に応じて縮小 |
| 並列ワーカー数 | 同時に攻撃するブラウザ数 | `1`。確認後に `2〜4` |
| ペイロード上限/フィールド | フィールド×チェックの標準投入上限 | `0` は無制限。初回は小さくしてもよい |
| リクエスト間隔 | リクエスト間の待機秒 | 既定 `0.5`。負荷を下げるなら増やす |
| ページ遷移リトライ | 一時的な遷移失敗の再試行回数 | 既定 `2` |
| 検査時間帯 | 検査可能/停止時間帯を1行1件で指定。例: `Mon-Fri 22:00-06:00` | 任意。空欄なら無効 |
| Proxy | Burp Suite / mitmproxy 等 | 必要な場合のみ |
| TLS | mTLS、PFX、CA、検証。サーバー配備時はブラウザからアップロード可 | 必要な場合のみ |

### 設定タブ

| タブ | 主な用途 |
| --- | --- |
| 基本設定 | Depth、Timeout、Forms、並列、負荷、Proxy、TLS、Headless |
| 検査項目 | XSS、SQLi、CSRF、CORS、SSRF、JWT、CMS などを選択 |
| 認証・Cookie | Cookie、自動ログイン、低権限 Cookie、ネイティブ TOTP、Bearer/カスタムヘッダ、複数アカウント |
| LLM設定 | provider、モデル、OpenAI互換 URL、役割別モデル |
| 機能フラグ | Planner、AI 分析、WAF、学習、community ペイロード、sitemap、SPA、巡回レビュー |
| スコープ・除外 | 攻撃対象、アクセスのみ、除外 URL、除外フィールド |
| 手動巡回 | 可視/遠隔ブラウザ、URL リストからシードを作成 |
| 攻撃フロー | ログイン、入力、クリック、待機など複数手順を定義 |
| Agent Browser | LLM 自律操作モード |
| ハイブリッド | Agent 偵察から通常スキャンへ引き渡すモード |

機能フラグの「SPA クロール (React/Vue/Angular)」は、CLI の `--spa-crawl` と同じ動作をします。(1) `history.pushState`/`replaceState` をフックし、ナビゲーション要素（nav リンク・タブ・`data-route` ボタンなど）をクリックして仮想ルートを発見しクロール対象に追加、(2) 描画確定待ち（`networkidle` 上限付き＋ルート要素の描画完了）で `<app-root>` が空のまま抽出されるのを防止、(3) 描画中に観測した攻撃スコープ内の GET API/XHR エンドポイント（クエリ付き。例: `/rest/products/search?q=`）を攻撃対象へ自動追加し URL パラメータとして注入検査、を行います。通常のリンクだけでは辿れない SPA でも検査対象が広がります。JSON ボディの POST エンドポイントへの注入は現状対象外です。既定はオフです。

### 認証とスコープ

認証が必要なら「認証・Cookie」で Cookie、ログイン URL、入力欄名、ユーザー名、パスワード、成功判定文字列を設定します。ログイン成否は URL 変化だけでなく、ログインフォームの残存、失敗メッセージ、MFA 画面の残留も使って判定します。

- 「攻撃対象」: 巡回もペイロード投入も許可する範囲。
- 「アクセスのみ許可」: 外部 IdP やログイン補助など、到達は必要だが攻撃しない範囲。
- 「除外」: ログアウト、削除、決済、通知送信などを避ける範囲。

通常ツール層（`scan`）の TOTP は、`otpauth://` URI、Base32 シークレット、QR 画像からローカル生成できます。メールや従来の MCP 方式も利用できます。Bearer トークンまたは1行1件のカスタムヘッダは通常スキャンの crawl と全 HTTP リクエストに加え、Agent と Hybrid Phase 1 の Agent 偵察にも付きます。Hybrid Phase 2 も同じ実効ヘッダを使います。`Authorization` をカスタムヘッダで明示した場合は Bearer 欄より優先されます。TOTP URI/シークレットと Bearer は実行時だけ使われ、設定 export やブラウザ保存には含まれません。詳しくは [README の MFA](../README.md#13-認証mfaスコープtls) を参照してください。

![認証タブ: ネイティブ TOTP と Bearer/カスタムヘッダ](images/dashboard-auth.png)

### Proxy と TLS

Burp Suite 等で通信を見る場合:

```text
http://127.0.0.1:8080
```

mTLS では PEM のクライアント証明書/秘密鍵、または Playwright 用 PFX/PKCS#12 を指定します。CA バンドルと「TLS証明書を検証」は httpx の直接リクエストに使われます。Playwright 側は HTTPS エラーを許容しながらクライアント証明書を提示します。

### サーバー配備時のファイルアップロード

リモートのダッシュボードでは、次の入力をブラウザからアップロードしてサーバー側パス欄へ自動反映できます。

- TLS クライアント証明書、秘密鍵、PFX/PKCS#12、CA バンドル
- カスタムペイロードファイル
- 手動巡回 JSON（通常設定と巡回レビュー）
- TOTP QR 画像

ファイルは `output/uploads/` に保存され、1ファイル 8MBまでです。拡張子は入力用途に応じた許可リストで制限されます。既存のサーバー側パス手入力も利用できます。`output_dir` と手動巡回の保存先は出力先なのでアップロード対象ではなく、リモート配備では空欄（自動）を推奨します。

## 6. Agent / Hybrid タブを設定する

![Agent Browser とハイブリッドの設定タブ](images/dashboard-hybrid.png)

### Agent Browser

「Agent Browser」タブでは次を設定します。

- LLM provider: Claude / OpenAI / Ollama
- モデル名: 空なら provider 既定
- 最大ステップ数: 既定 `100`
- 検査項目: Agent 対応種別から選択
- ログイン URL、ユーザー名、パスワード

Bearer/カスタムヘッダは「認証・Cookie」の設定を引き継ぎます。「Agent Browser スキャン開始」を押すと、LLM がブラウザを観察し、ページ遷移、入力、ペイロード選択、結果判断を自律的に行います。Agent の独自性を残す設計のため、Finding は未確証でもレポートへ残ります。

### Hybrid

「ハイブリッド」タブでは、偵察用 provider、モデル、最大ステップ数（既定 `30`）、Ollama URL を設定します。ログイン情報、Bearer/カスタムヘッダとチェック種別は「認証・Cookie」「検査項目」の設定を引き継ぎます。

Hybrid の処理:

```text
Phase 1: Agent が探索
  ├─ 発見した URL
  └─ Agent Finding（脆弱性仮説）
              ↓
Phase 2: 発見 URL をシードに通常スキャン
              ↓
最終レポート: 決定論 Finding + Agent Finding をラベル付きで併記
```

Agent Finding は `🤖 Agent発見（LLM独自解釈・未確証）` として表示されます。決定論的な再現確認が付いた Agent Finding は、さらに `✅ 決定論的にも再現確認済み` と表示されます。Hybrid は Agent を偵察だけに使うモードではありません。

## 7. スキャンを開始する

### 通常モード

画面下部の「スキャン開始」を押します。Planner の対話確認を有効にしている場合は、巡回後に検査対象フィールド、チェック、カスタムペイロードを確認し、「攻撃開始」を押します。

巡回レビューを有効にしている場合は、画面遷移図を確認し、そのまま検査、再巡回、URL追加、手動巡回追加、シナリオ作成を選べます。

### Agent / Hybrid

各タブ内の専用開始ボタンを押します。通常設定画面下部の「スキャン開始」は通常モードの入口なので、モードを間違えないよう注意してください。

## 8. 実行中の状態を確認する

![スキャン実行中](images/dashboard-running.png)

通常スキャンの主なフェーズは次のとおりです。

```text
Crawl -> Plan -> Attack -> Report
```

画面では次を確認できます。

| 場所 | 内容 |
| --- | --- |
| ヘッダー | フェーズ、進捗率、残り推定、完了予定 |
| 巡回マップ | 発見ページ、巡回中/完了/検出状態 |
| ブラウザ | 実行中のスクリーンショット |
| 進捗 | チェック種別ごとの進行状況 |
| Current Test | URL、Field、Check、Payload |
| Findings | 重要度、種別、URL、Evidence |
| Request / Response | 直近の通信 |
| Event Log | 認証、再試行、LLM、エラー、フェーズ変更 |

上部の介入バーから、一時停止、再開、現在フィールドのスキップ、現在ページのスキップ、中断、手動ペイロード実行を行えます。中断すると、その時点までの Finding で部分レポートを保存します。

Hybrid では Event Log に Phase 1 の URL 数と Agent Finding 数、Phase 2 の開始が表示されます。Phase 1 が失敗した場合は警告を出し、URL シードと Agent Finding なしで通常スキャンを続行します。

## 9. 結果と Finding を読む

![検出結果の表示](images/dashboard-results.png)

Finding では、重要度だけでなく確証と出自を確認します。

| 項目 | 確認内容 |
| --- | --- |
| Severity | Critical / High / Medium / Low / Info。対応優先度の目安 |
| Type | XSS、SQLi、CSRF などの検査種別 |
| URL / Field | どのページ、パラメータ、入力欄、ヘッダか |
| Evidence | alert 発火、レスポンス差分、エラー、ヘッダ等 |
| Request / Response | 実際の投入と応答 |
| `verified` | Finding を保持する互換フラグ。`true` でも `assumed` の場合がある |
| `verification_state` | `reproduced`（再現済み）/ `assumed`（推定・再検証未実行）/ `unreproduced`（非再現）/ `skipped`（検証 skip）。空は旧 Finding |
| `confidence` | `confirmed` / `likely` / `tentative` |
| `evidence_type` | 判定に使った構造化シグナル |
| `source` | `scanner`（通常）/ `agent`（Agent） |
| `agent_verified` | Agent Finding を決定論的にも再現したか |

HTML レポートのバッジ:

- `🤖 Agent発見（LLM独自解釈・未確証）`: Agent の仮説。人手で証拠と再現手順を確認する。
- `✅ 決定論的にも再現確認済み`: Agent Finding に決定論的確認が付いている。
- `〜 推定（再検証未実行）`: 通常 Finding を検証できなかったため保持している。再現済みではない。
- `⚠ 要確認`: 2回目に再現しなかったか、例外で検証を skip した Finding。詳細は `verification_note` を確認する。
- バッジなし: 通常の決定論スキャナ由来。

`severity=critical` でも Agent 未確証なら確証済みとは扱いません。通常 Finding でも `verification_state=assumed`、`confidence=tentative`、`verified=false` の場合は追加確認が必要です。

## 10. レポートと証跡を確認する

完了後、ポータルの履歴から HTML、JSON、ダウンロードを開けます。ファイルは `output/<日時>/` に保存されます。

| ファイル | 内容 |
| --- | --- |
| `report.html` | Finding、Evidence、Agent バッジを含む HTML |
| `report_executive.html` | 管理層向けサマリー |
| `report_developer.html` | 開発者向け詳細 |
| `evidence.json` | Finding と証跡 JSON |
| `reproduction.json`, `reproduce.sh` | 再現情報 |
| `report.sarif` | CI/CD 用 SARIF。`source` 等を保持 |
| `remediation_plan.md`, `remediation_tasks.json` | 修正計画とタスク |
| `http_requests.jsonl`, `payloads.jsonl` | 通信と投入ペイロードの監査ログ |
| `scan_config.json` | 実行設定。秘匿値は伏字 |
| `checkpoint.json` | 再開用の完了単位と Finding |

HTML レポートと Evidence を確認し、必要なら再現物で人手検証してから修正タスク化します。

## 11. 長時間スキャンと再開

通常スキャンはチェックポイントを既定で保存します。ブラウザ停止、ネットワーク断、時間帯待機、中断後は CLI で再開できます。

```bash
python3 main.py scan https://example.com \
  --resume output/20260721_010203
```

通常攻撃の例外終了単位と、adaptive LLM の一時失敗は未完了として残ります。adaptive はチェック種別単位で完了を記録するため、成功済みチェックを繰り返さず、失敗分だけを回収します。provider 自体が恒久的に不達の場合は決定論 fallback で完了し、resume の無限再試行を避けます。

ダッシュボードから開始したスキャンの `checkpoint.json` も同じ出力ディレクトリに保存されます。再開は現時点では CLI の `--resume` を使用します。

## 12. よくあるつまずき

### 対象にアクセスできない

ブラウザから Target URL を開けるか、VPN、DNS、IP 制限、Proxy、mTLS、CA を確認します。Event Log と `http_requests.jsonl` も確認してください。

### ログイン後の画面を検査できない

Cookie、ログイン URL、入力欄名、成功判定文字列、MFA を確認します。セッションが短い場合は Event Log の `Session expired` と再ログイン結果を確認し、認証済みページに必ず出る文字列を CLI の `--logged-in-marker` で補強できます。

### SPA のページが足りない

「精度重視診断」または SPA Crawl を有効にし、手動巡回、遠隔ブラウザ、URL リスト、HAR、OpenAPI/Postman でシードを補います。

### 検出が少ない

チェック種別、Depth、Max Forms、ペイロード上限、除外、認証スコープを確認します。高速プロファイルは網羅性より時間を優先します。

### Agent / Hybrid が動かない

`requirements-agent.txt`、API キー、モデル名、Ollama URL を確認します。ダッシュボードの Agent/Hybrid provider は Claude、OpenAI、Ollama です。Gemini を使う場合は通常スキャンの LLM 設定を使用してください。

### LLM の一時失敗がある

`config/wscan.yaml` の `llm.timeout_seconds` と `llm.max_retries` を調整します。通常スキャンは fallback で継続します。adaptive の未完了分は `--resume` で回収します。

### 対象への負荷を下げたい

Depth、Max Forms、ペイロード上限、並列数を下げ、リクエスト間隔を増やします。状態変更プローブは有効にしないでください。

詳細な切り分けは [トラブルシューティング](troubleshooting_ja.md)、実検査前の準備は [運用ガイド](operation_guide_ja.md) を参照してください。

## 13. 最短手順まとめ

```bash
python3 main.py serve --host 127.0.0.1 --port 8765
```

1. `http://localhost:8765/` を開き、「新規スキャン」を押す。
2. Target URL とプロファイルを指定する。
3. 認証、スコープ、検査項目、負荷を確認する。
4. 通常は画面下部、Agent/Hybrid は各タブ内の開始ボタンを押す。
5. 実行中は Event Log、Current Test、Request/Response、Findings を確認する。
6. 完了後は Agent バッジ、Evidence、再現物、HTML/JSON/SARIF を確認する。
