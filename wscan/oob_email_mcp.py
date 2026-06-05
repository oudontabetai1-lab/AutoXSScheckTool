"""OOB メール受信を MCP サーバとして公開する。

専用メールボックス（IMAP / POP3）を監視し、blind XSS / SSRF・メールヘッダ
インジェクション等の OOB 確証に使う。`wscan/oob_email.py` の受信ロジックを
MCP ツールとして薄くラップしたもの。

ツール:
- ``generate_oob_target``  : ペイロードへ埋め込む一意トークンと受信アドレスを払い出す
- ``check_oob_email``       : トークンに一致するメールを即時検索する
- ``wait_oob_email``        : トークン一致メールが届くまで待機する
- ``oob_status``            : 受信設定の状態を返す（接続情報は伏せる）

実行:
    pip install -r requirements-mcp.txt   # mcp パッケージを導入
    # 環境変数で受信ボックスを設定（README/docs 参照）
    python -m wscan.oob_email_mcp          # stdio トランスポートで起動

設定（環境変数）:
    WSCAN_OOB_PROTOCOL   imap | pop3        (既定: imap)
    WSCAN_OOB_HOST       受信サーバホスト
    WSCAN_OOB_PORT       ポート（省略時はプロトコル既定）
    WSCAN_OOB_USERNAME   ログインユーザ
    WSCAN_OOB_PASSWORD   パスワード / アプリパスワード
    WSCAN_OOB_SSL        true | false       (既定: true)
    WSCAN_OOB_MAILBOX    IMAP のフォルダ    (既定: INBOX)
    WSCAN_OOB_DOMAIN     OOB アドレスの catch-all ドメイン
"""
from __future__ import annotations

from .oob_email import (
    EmailSink,
    OOBEmailConfig,
    make_oob_token,
    oob_address,
)


def build_server():
    """FastMCP サーバを構築して返す（mcp 未導入なら明示的に失敗させる）。"""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - 依存未導入時のガイダンス
        raise SystemExit(
            "MCP server requires the 'mcp' package. "
            "Install it with: pip install -r requirements-mcp.txt"
        ) from exc

    mcp = FastMCP("wscan-oob-email")

    def _sink() -> EmailSink:
        return EmailSink(OOBEmailConfig.from_env())

    @mcp.tool()
    def generate_oob_target(scan_id: str = "") -> dict:
        """OOB 検査用の一意トークンと受信アドレスを払い出す。

        払い出した ``token`` をペイロードに埋め込み、後で ``check_oob_email`` /
        ``wait_oob_email`` に同じ ``token`` を渡して着信を確認する。
        """
        cfg = OOBEmailConfig.from_env()
        token = make_oob_token(scan_id)
        address = oob_address(token, cfg.domain) if cfg.domain else ""
        return {"token": token, "address": address, "domain": cfg.domain}

    @mcp.tool()
    def check_oob_email(token: str) -> dict:
        """トークンに一致するメールを即時検索する（待機しない）。"""
        hits = _sink().search(token)
        return {"token": token, "count": len(hits), "emails": [h.to_dict() for h in hits]}

    @mcp.tool()
    def wait_oob_email(token: str, timeout: float = 60.0, interval: float = 5.0) -> dict:
        """トークン一致メールが届くまで最大 ``timeout`` 秒待機する。"""
        hit = _sink().wait_for(token, timeout=timeout, interval=interval)
        return {
            "token": token,
            "received": hit is not None,
            "email": hit.to_dict() if hit else None,
        }

    @mcp.tool()
    def oob_status() -> dict:
        """受信設定の状態を返す（パスワード等の機微情報は含めない）。"""
        cfg = OOBEmailConfig.from_env()
        return {
            "configured": cfg.configured,
            "protocol": cfg.protocol,
            "host": cfg.host,
            "port": cfg.effective_port,
            "mailbox": cfg.mailbox,
            "domain": cfg.domain,
            "ssl": cfg.use_ssl,
        }

    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
