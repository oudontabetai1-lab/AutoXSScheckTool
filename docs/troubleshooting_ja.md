# WScan トラブルシューティング

このドキュメントでは、WScan の実行中に起きやすい「アクセスできない」「検査が途切れる」「検出できない」「画面に反映されない」問題の切り分け方法をまとめます。

## まず確認すること

問題が起きたら、最初に次を確認してください。

```bash
python3 main.py --help
python3 main.py serve --port 8765
```

別ターミナルで対象 URL に到達できるか確認します。

```bash
curl -I https://example.com
```

ローカルや検証環境の場合は、ブラウザで直接 Target URL を開き、ログイン、画面遷移、フォーム表示が手動でできるか確認します。

## ダッシュボードが開けない

### 症状

- `http://localhost:8765` が開けない。
- ブラウザに接続エラーが出る。
- ターミナルにポート競合エラーが出る。

### 対処

別ポートで起動します。

```bash
python3 main.py serve --port 8766
```

macOS でポート利用状況を見る場合:

```bash
lsof -i :8765 -P -n
```

ダッシュボードは起動しているが表示が古い場合は、ブラウザを再読み込みします。WebSocket が切れている場合は、ダッシュボードサーバーを再起動してください。

## Target URL にアクセスできない

### 症状

- Crawl フェーズで失敗する。
- Event Log に navigation timeout や connection refused が出る。
- Findings が 0 のまま終了する。

### 原因候補

| 原因 | 確認方法 |
| --- | --- |
| URL 誤り | ブラウザで直接開く |
| VPN 未接続 | 社内 URL に curl / ブラウザで到達できるか確認 |
| DNS / hosts 問題 | `curl -v` や `dig` で確認 |
| 自己署名証明書 | ブラウザで証明書エラーが出ていないか確認 |
| クライアント証明書必須 | mTLS 証明書未指定時に 400/403/接続拒否になっていないか確認 |
| プロキシ必須 | `--proxy` を指定 |
| IP 制限 | 検査端末の送信元 IP を確認 |
| WAF / Bot 対策 | 403、429、CAPTCHA、ブロックページを確認 |

### 対処

まず手動で対象 URL を開ける状態にします。プロキシが必要な環境では、ダッシュボードの Proxy または CLI の `--proxy` を指定します。

```bash
python3 main.py scan https://example.com --proxy http://127.0.0.1:8080
```

一時的なタイムアウトがある場合は、再試行回数と待機時間を増やします。

```bash
python3 main.py scan https://example.com \
  --navigation-retries 3 \
  --timeout 60 \
  --delay 1.0
```

## クライアント証明書が必要なサイトに入れない

### 症状

- ブラウザで証明書選択や 400/403 が出る。
- ダッシュボードからの Crawl がすぐ失敗する。
- httpx 系のスキャナだけ失敗し、ブラウザ表示は成功する。

### 対処

PEM のクライアント証明書と秘密鍵がある場合:

```bash
python3 main.py scan https://secure.example.com \
  --tls-client-cert /path/to/client.crt \
  --tls-client-key /path/to/client.key
```

社内CA/自己署名CAも検証する場合:

```bash
python3 main.py scan https://secure.example.com \
  --tls-client-cert /path/to/client.crt \
  --tls-client-key /path/to/client.key \
  --tls-ca-cert /path/to/ca.pem \
  --tls-verify
```

PFX/PKCS#12 しかない場合:

```bash
python3 main.py scan https://secure.example.com \
  --tls-client-pfx /path/to/client.p12 \
  --tls-client-cert-password 'password'
```

注意点:

- PEM の cert/key は Playwright と httpx の直接リクエストの両方で使用されます。
- PFX は Playwright ブラウザアクセスで使用されます。httpx 系の直接リクエストにも同じ証明書が必要な場合は、PEM 形式も用意してください。
- `--tls-verify` をオンにした場合、CA が信頼できないと接続に失敗します。社内CAの場合は `--tls-ca-cert` を指定してください。
- 証明書パスは WScan を実行している端末から読める絶対パスを推奨します。

## 検査が途中で途切れる

### 症状

- 途中でブラウザ操作が止まる。
- WebSocket が切断される。
- Report 生成まで進まない。
- 一部ページだけ検査されない。

### 対処

対象サイトが遅い場合は、タイムアウトとリトライを増やします。

```bash
python3 main.py scan https://example.com \
  --timeout 60 \
  --navigation-retries 3
```

負荷やレート制限が疑われる場合は、リクエスト間隔を長くし、並列数を 1 にします。

```bash
python3 main.py scan https://example.com \
  --delay 1.0 \
  --concurrency 1 \
  --max-payloads 5
```

ブラウザ上の UI が頻繁に変わるサイトでは、まず `--fast --depth 1` で小さく確認し、手動クロールや HAR で対象 URL を補います。

## ログイン後のページを検査できない

### 症状

- ログインページだけが検査される。
- 認証後ページに到達しない。
- 検査中にログアウト扱いになる。
- Event Log に session expired が出る。

### 対処

Cookie が使える場合は、ログイン済みブラウザから Cookie を取得して渡すのが安定します。

```bash
python3 main.py scan https://app.example.com \
  --cookie-file cookies.json
```

フォームログインを使う場合は、ログイン URL と認証情報を指定します。

```bash
python3 main.py scan https://app.example.com \
  --login-url https://app.example.com/login \
  --auth-user user@example.com \
  --auth-pass 'password' \
  --login-success dashboard
```

SSO や MFA がある場合は、自動ログインよりも Cookie、手動クロール、HAR の利用を検討してください。

## 検出できない、見逃しが疑われる

### 症状

- 明らかな脆弱性があるのに Findings が出ない。
- フォームはあるが攻撃対象になっていない。
- SPA の画面がクロールされない。

### 原因候補

| 原因 | 対処 |
| --- | --- |
| クロールできていない | `--depth` を増やす、手動クロール、HAR を使う |
| SPA の動的ルート | 固有マーカー検出時は既定で自動有効化。検出されない構成は `--spa-crawl` を明示し、`--no-auto-spa` が付いていないか確認する |
| フォーム数上限 | `--max-forms` を増やす |
| ペイロード数上限 | `--max-payloads` を増やす |
| チェック未選択 | `--checks` またはダッシュボードのチェックタブを確認 |
| 認証切れ | Cookie / Login URL / Header を見直す |
| WAF で遮断 | `--delay` を増やし、Proxy で応答を確認 |
| 入力が特殊 | Attack Flow、手動クロール、HAR で操作手順を補う |

例:

```bash
python3 main.py scan https://app.example.com \
  --checks xss dom_xss stored_xss sqli open_redirect csrf \
  --depth 3 \
  --spa-crawl \
  --max-forms 100 \
  --max-payloads 20
```

## UI に結果が反映されない

### 症状

- ターミナルでは検出されているが、ダッシュボードに Finding が出ない。
- Event Log が更新されない。
- リロード後に状態が消える。

### 対処

ダッシュボードは WebSocket でリアルタイム更新します。ブラウザの再読み込み、サーバー再起動、別ポート起動を試してください。

```bash
python3 main.py serve --port 8766
```

最終結果は `output/<timestamp>/` のファイルを正とします。UI 表示が途切れた場合でも、`evidence.json`、`report.html`、`scan_config.json` を確認してください。

```bash
ls -la output/
```

## レポートが開けない

### 症状

- スキャン完了後に HTML レポートが自動で開かない。
- `report.html` が見つからない。

### 対処

出力ディレクトリを確認します。

```bash
find output -maxdepth 2 -name report.html | sort
```

自動オープンを使わない場合は、`--no-open-report` を指定して、後から手動で `report.html` を開きます。

```bash
python3 main.py scan https://example.com --no-open-report
```

## ペイロード学習ファイルが更新される

### 症状

- 検査後に `config/payload_learning.json` が作成または更新される。

### 説明

これは成功/失敗したペイロードを次回以降に活かすための学習データです。検査結果をリポジトリに含めたくない場合は、コミット対象から外してください。

学習を無効化する場合:

```bash
python3 main.py scan https://example.com --no-payload-learning
```

別ファイルに保存する場合:

```bash
python3 main.py scan https://example.com --learning-file /tmp/wscan_payload_learning.json
```

## WAF やレート制限に当たる

### 症状

- 403、406、429 が増える。
- CAPTCHA やブロックページが返る。
- 途中から全リクエストが失敗する。

### 対処

検査強度を落とします。

```bash
python3 main.py scan https://example.com \
  --delay 2.0 \
  --concurrency 1 \
  --max-payloads 5 \
  --navigation-retries 3
```

WAF の検知を確認するには、プロキシでレスポンス本文とヘッダを見ます。許可された検査であっても、WAF 管理者に時間帯と送信元 IP を共有してから実施してください。

## 問題報告時に集める情報

バグ報告や再現確認では、次を揃えると切り分けしやすくなります。

- 実行コマンド、またはダッシュボードで設定した項目。
- `output/<timestamp>/scan_config.json`
- `output/<timestamp>/evidence.json`
- `output/<timestamp>/report.html`
- ターミナル出力のエラー部分。
- 対象 URL が手動ブラウザで開けるかどうか。
- 認証方式、Cookie の有効期限、プロキシ利用有無。
- 期待した検出内容と、実際の Findings。
