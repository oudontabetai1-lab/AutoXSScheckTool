# サーバーホスティング / イントラネット公開ガイド

WScan のダッシュボードをサーバー上で常時起動し、社内ネットワーク（イントラネット）の
ブラウザから操作するための手順をまとめます。`serve` モードは常駐型に対応しており、
1 度の起動で何度でもスキャンを実行できます。

> ⚠️ **セキュリティ上の注意**
> WScan は実際に攻撃ペイロードを送信する強力なツールです。ネットワークに公開する場合は
> **必ずアクセストークン（`--auth-token` / `WSCAN_AUTH_TOKEN`）を設定**してください。
> トークン未設定の場合、ポートに到達できる全員がスキャナーを操作できてしまいます。

---

## 1. 概要 — サーバーモードの挙動

`python main.py serve` は次のように動作します。

- 既定で `0.0.0.0` にバインドし、同一イントラネット内の他端末からアクセス可能。
- アクセストークンを設定するとログイン画面が表示され、未認証アクセスは拒否されます。
  - ブラウザ（`Accept: text/html`）→ `/login` へリダイレクト
  - API / XHR → `401 Unauthorized` (JSON)
- スキャン完了後もサーバーは終了せず、ダッシュボードは次のスキャン入力待ちに戻ります。
- ヘッドレスサーバーではホスト側ブラウザを自動起動しません（`--no-open-browser` 既定）。

### 画面構成（サーバーポータル）

サーバー利用に最適化した 2 画面構成です。

| パス | 画面 | 役割 |
| --- | --- | --- |
| `/` | **ポータル** | スキャン履歴一覧、レポートのブラウザ閲覧 / ダウンロード、成果物の一括 zip ダウンロード・削除、実行中スキャンの状態表示と停止、新規スキャン起動 |
| `/monitor` | **ライブモニター** | スキャン設定フォームと、実行中のリアルタイム進捗（WebSocket）。攻撃プラン確認・手動ペイロード等の高度機能 |

- **レポートはブラウザから直接閲覧できます**（リモートでもサーバー側ファイルパスを開く必要はありません）。
  各スキャンの成果物は `/reports/<scan_id>/report.html` で配信され、関連アセット（スクリーンショット・
  `evidence.json` 等）も同じフォルダから提供されます。
- 履歴はサーバーの `output/`（コンテナでは `/app/output` ボリューム）配下を走査して生成されます。
- 実行中のスキャンはポータルの「停止」または `/monitor` の「中断」から停止でき、部分レポートが保存されます。

#### ポータル / 管理系の主な API

| メソッド・パス | 用途 |
| --- | --- |
| `GET /api/v1/scans` | スキャン履歴（対象・検出数・重大度内訳・状態）の一覧 |
| `GET /reports/{scan_id}/report.html` | レポートをブラウザで閲覧 |
| `GET /api/v1/scans/{scan_id}/download` | 成果物フォルダを zip でダウンロード |
| `DELETE /api/v1/scans/{scan_id}` | スキャン成果物を削除（実行中スキャンは不可） |
| `GET /api/v1/scans/{scan_id}/diff` | 同一対象の前回スキャンとの差分（新規/修正済み/継続） |
| `POST /api/v1/scans/prune` | 保持ポリシーを今すぐ適用し古いスキャンを削除（ポータルの「🧹 整理」ボタン） |
| `POST /api/v1/scan/abort` | 実行中スキャンの停止を要求 |
| `GET/POST /api/v1/settings` | 通知(Slack/Webhook)設定の取得・更新（`POST /api/v1/settings/test` でテスト送信） |
| `GET/POST /api/v1/schedules` | 定期スキャンの一覧・登録（`{id}/toggle` で有効切替、`DELETE` で削除） |

`GET /api/v1/scans` のレスポンスには履歴 `scans` に加え、合計使用量と保持ポリシーを示す
`storage`（`total_bytes` / `scan_count` / `retention_days` / `retention_max_scans`）が含まれます。
ポータル上部に使用量と保持設定が表示されます。

### 主なオプション / 環境変数

| 項目 | CLI フラグ | 環境変数 | 既定値 |
| --- | --- | --- | --- |
| バインドアドレス | `--host` | `WSCAN_HOST` | `0.0.0.0` |
| ポート | `--port` | （`config/wscan.yaml` の `port`） | `8765` |
| アクセストークン | `--auth-token` | `WSCAN_AUTH_TOKEN` | （無効） |
| ブラウザ自動起動 | `--open-browser` / `--no-open-browser` | — | localhost バインド時のみ起動 |
| 出力の保持日数 | （`config/wscan.yaml` の `retention_days`） | `WSCAN_RETENTION_DAYS` | `0`（無制限） |
| 出力の保持件数 | （`config/wscan.yaml` の `retention_max_scans`） | `WSCAN_RETENTION_MAX_SCANS` | `0`（無制限） |

保持ポリシー（`retention_days` / `retention_max_scans`）を設定すると、serve 起動時と各スキャン完了時に
`output/` 配下の古いスキャン成果物が自動削除されます（実行中スキャンは保護）。0 のときは無制限（既定）。
ディスクを圧迫しがちな長期運用サーバーでの肥大化防止に有効です。

トークンは推測されにくい長い文字列を使ってください。

```bash
openssl rand -hex 16   # 例: トークン生成
```

---

## 2. 直接起動（最小構成）

```bash
pip install -r requirements.txt
playwright install --with-deps chromium

export WSCAN_AUTH_TOKEN="$(openssl rand -hex 16)"
echo "Token: $WSCAN_AUTH_TOKEN"   # 利用者に共有

python3 main.py serve --host 0.0.0.0 --port 8765 --no-open-browser
```

起動時のパネルに、バインド先・推定イントラネット URL・認証状態が表示されます。
社内の端末から `http://<サーバーのLAN IP>:8765` を開き、トークンでログインします。

---

## 3. Docker / docker-compose（推奨）

Chromium と依存ライブラリを同梱したコンテナとして配布できます。

```bash
# 1) トークンを設定
export WSCAN_AUTH_TOKEN="$(openssl rand -hex 16)"

# 2) ビルド & 起動（バックグラウンド）
docker compose up -d --build

# 3) アクセス
#    http://<サーバーのLAN IP>:8765  （トークンでログイン）

# ログ確認 / 停止
docker compose logs -f
docker compose down
```

- 生成レポートはホストの `./output` に永続化されます。
- `./config/wscan.yaml` を編集すればスキャン既定値を再ビルドなしで変更できます。
- LLM を使う場合は `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` を
  環境変数として渡してください（`docker-compose.yml` 参照）。
- Chromium 向けに `shm_size: 1gb` を指定済みです。

`docker run` 単体で起動する場合:

```bash
docker build -t wscan:latest .
docker run -d --name wscan -p 8765:8765 --shm-size=1g \
  -e WSCAN_AUTH_TOKEN="$(openssl rand -hex 16)" \
  -v "$(pwd)/output:/app/output" \
  wscan:latest
```

---

## 4. リバースプロキシ / HTTPS

社内で TLS 終端を行うリバースプロキシ（Nginx 等）の背後に置く場合、WebSocket の
アップグレードを通すよう設定してください。ダッシュボードは HTTPS 配信時に自動で
`wss://` へ切り替わります。

```nginx
server {
    listen 443 ssl;
    server_name wscan.intra.example.com;
    # ssl_certificate / ssl_certificate_key ...

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_read_timeout 3600s;   # 長時間スキャン中の WS 切断を防ぐ
    }
}
```

プロキシで TLS を終端する場合、WScan 自体は `127.0.0.1` バインドに絞ると安全です
（`--host 127.0.0.1`）。

---

## 5. API / CI からの利用

トークン設定時は、API 呼び出しに `Authorization: Bearer <token>` を付与します。

```bash
TOKEN=xxxxxxxx
BASE=http://wscan.intra.example.com:8765

# スキャン開始
curl -s -X POST "$BASE/api/v1/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"config": {"url": "https://target.intra.example.com", "checks": ["xss","sqli"]}}'

# ステータス / 結果取得
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/scan/status"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/scan/results"
```

非ブラウザの WebSocket クライアントは `ws://<host>:<port>/ws?token=<token>` で接続できます。
`/health` のみ認証不要です（コンテナのヘルスチェック用）。

---

## 6. トラブルシュート

| 症状 | 対処 |
| --- | --- |
| 他端末からアクセスできない | `--host 0.0.0.0` で起動しているか、サーバーのファイアウォールで該当ポートが開いているか確認 |
| ログイン後すぐ弾かれる | トークンが一致しているか確認。Cookie をブロックしていないか確認 |
| WebSocket が切れる | リバースプロキシの `Upgrade`/`Connection` ヘッダと `proxy_read_timeout` を確認 |
| Chromium が起動しない (Docker) | `--shm-size=1g` を指定しているか確認 |
| ブラウザがサーバー上で開く | `--no-open-browser` を付ける（Docker 起動時は既定で無効） |
