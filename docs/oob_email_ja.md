# OOB（帯域外）メール受信と MCP 化

Blind XSS / SSRF、メールヘッダインジェクション、second-order injection など、
**対象アプリがメールを送って初めて確証できる**脆弱性を自動確認するための、
専用受信メールボックス（POP3 / IMAP）と MCP サーバの設定手順です。

## 仕組み

```
スキャナ ──(一意トークン入りペイロード投入)──▶ 対象アプリ
                                                  │ 脆弱性が発火しメール送信
                                                  ▼
   専用 catch-all メールボックス  ◀── MCP: check_oob_email / wait_oob_email
                │
   トークン一致を確認 → Finding を「確証済み」に昇格
```

1. `generate_oob_target` で一意トークン（例: `wscan-oob-<scan_id>-<nonce>`）と
   受信アドレス `<token>@<catch-all-domain>` を払い出す。
2. そのトークン／アドレスをペイロードに埋め込み対象へ送信。
3. 着信を `check_oob_email`（即時）または `wait_oob_email`（待機）で確認。
   To ヘッダ・件名・本文のいずれかにトークンを含むメールを一致とみなす。

## 1. 受信メールボックスの用意

- OOB 専用ドメイン（例 `oob.example.com`）を用意し、**catch-all（ワイルドカード）**
  受信を有効化する。任意の `<token>@oob.example.com` 宛が1つの受信箱に集約される。
- DNS に MX レコードを設定し、受信サーバを指す。
- 受信用アカウント（IMAP もしくは POP3）を1つ作成する。Gmail 等を使う場合は
  アプリパスワードを発行する。

> 注: 本機能は受信箱の内容を読み取ります。検査専用の隔離アカウントを使い、
> 業務メールと混在させないでください。

## 2. 環境変数で設定

| 変数 | 説明 | 既定 |
|---|---|---|
| `WSCAN_OOB_PROTOCOL` | `imap` または `pop3` | `imap` |
| `WSCAN_OOB_HOST` | 受信サーバホスト | （必須） |
| `WSCAN_OOB_PORT` | ポート | 省略時はプロトコル既定（IMAPS 993 / POP3S 995） |
| `WSCAN_OOB_USERNAME` | ログインユーザ | （必須） |
| `WSCAN_OOB_PASSWORD` | パスワード / アプリパスワード | （必須） |
| `WSCAN_OOB_SSL` | `true` / `false` | `true` |
| `WSCAN_OOB_MAILBOX` | IMAP のフォルダ | `INBOX` |
| `WSCAN_OOB_DOMAIN` | OOB アドレスの catch-all ドメイン | （アドレス払い出しに必要） |

```bash
export WSCAN_OOB_PROTOCOL=imap
export WSCAN_OOB_HOST=imap.example.com
export WSCAN_OOB_USERNAME=oob@oob.example.com
export WSCAN_OOB_PASSWORD=********
export WSCAN_OOB_DOMAIN=oob.example.com
```

## 3. MCP サーバの起動

```bash
pip install -r requirements-mcp.txt   # mcp パッケージを導入
python -m wscan.oob_email_mcp          # stdio トランスポートで起動
```

公開ツール:

| ツール | 用途 |
|---|---|
| `generate_oob_target(scan_id="")` | トークンと受信アドレスを払い出す |
| `check_oob_email(token)` | トークン一致メールを即時検索 |
| `wait_oob_email(token, timeout=60, interval=5)` | 着信まで待機 |
| `oob_status()` | 受信設定の状態（機微情報は伏せる） |

## 4. MCP クライアントへの登録例

Claude Code / Claude Desktop の MCP 設定（stdio）例:

```json
{
  "mcpServers": {
    "wscan-oob-email": {
      "command": "python",
      "args": ["-m", "wscan.oob_email_mcp"],
      "env": {
        "WSCAN_OOB_HOST": "imap.example.com",
        "WSCAN_OOB_USERNAME": "oob@oob.example.com",
        "WSCAN_OOB_PASSWORD": "********",
        "WSCAN_OOB_DOMAIN": "oob.example.com"
      }
    }
  }
}
```

## 5. プログラムからの利用

```python
from wscan.oob_email import EmailSink, OOBEmailConfig, make_oob_token, oob_address

cfg = OOBEmailConfig.from_env()
token = make_oob_token("scan-001")
address = oob_address(token, cfg.domain)   # token を payload / 宛先に埋め込む

# … ペイロード送信後 …
sink = EmailSink(cfg)
hit = sink.wait_for(token, timeout=120)
if hit:
    print("OOB confirmed:", hit.subject, hit.from_addr)
```

`wscan/oob_email.py` の解析・突合系（`parse_email` / `email_matches_token` /
`filter_messages`）はネットワーク非依存なので、受信ボックス無しでも単体テスト
できます（`tests/test_oob_email.py`）。
