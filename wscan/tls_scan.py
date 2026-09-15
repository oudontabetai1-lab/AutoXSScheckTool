"""TLS 通信路の設定不備検査（OSS の sslyze を活用）。

弱いプロトコル（SSLv2/SSLv3/TLS 1.0/1.1）の受理、Heartbleed / CCS Injection / ROBOT 等を
OSS の `sslyze` で検査する。sslyze は **optional 依存**（`requirements-tls.txt`）で、未導入なら
機能は inert（graceful）。判定（結果 → issue 一覧）は防御的な純粋関数 `extract_tls_issues` に分離し、
ネットワーク非依存でテスト可能にする。

外部送信はしない（対象ホストへ TLS ハンドシェイクするのみ）。opt-in（`features.tls_scan`）。
"""
from __future__ import annotations

from typing import Any, Optional


def sslyze_available() -> bool:
    """sslyze が import 可能かを返す（optional 依存）。"""
    try:
        import sslyze  # noqa: F401
        return True
    except Exception:
        return False


def _completed(attempt: Any) -> bool:
    """ScanCommandAttempt が COMPLETED かを防御的に判定する。"""
    try:
        status = getattr(attempt, "status", None)
        return status is not None and getattr(status, "name", "") == "COMPLETED"
    except Exception:
        return False


def server_scan_reachable(result: Any) -> bool:
    """sslyze が対象サーバへ到達し handshake できたかを防御的に判定する（純粋）。

    sslyze は接続不能でも ``ServerScanResult`` を返す（``connectivity_status=ERROR`` /
    ``scan_status`` が未完）。この場合を「到達成功・issue 無し」と取り違えないための判定。
    属性が無い版差では ``True``（従来どおり）にフォールバックし、過剰な抑制はしない。
    """
    conn = getattr(result, "connectivity_status", None)
    if conn is not None and getattr(conn, "name", "") not in ("", "COMPLETED"):
        return False
    scan = getattr(result, "scan_status", None)
    if scan is not None and getattr(scan, "name", "") not in ("", "COMPLETED"):
        return False
    return True


def _scan_fields() -> tuple[str, ...]:
    """検査対象コマンド（scan_result のフィールド名）。``_WEAK_PROTOCOLS`` 定義後に呼ぶ。"""
    return tuple(f for f, _, _ in _WEAK_PROTOCOLS) + (
        "heartbleed", "openssl_ccs_injection", "robot",
    )


def scan_has_completed_attempts(scan_result: Any) -> bool:
    """検査対象コマンドのうち 1 つ以上が COMPLETED したかを返す（純粋）。

    到達はしたが全コマンドが ERROR（部分 handshake 失敗等）のケースを「issue 無し」と
    区別するために使う（黙った偽陰性の可視化）。
    """
    sr = getattr(scan_result, "scan_result", None) or scan_result
    return any(_completed(getattr(sr, f, None)) for f in _scan_fields())


def incomplete_commands(scan_result: Any) -> list[str]:
    """要求したのに COMPLETED しなかったコマンド名の一覧を返す（純粋）。

    一部コマンドだけ ERROR（例: TLS1.0 は成功だが Heartbleed/ROBOT が失敗）でも、
    その失敗を黙って捨てて「issue 無しで検査成功」にしないためのシグナル（Codex #158）。
    存在するフィールドのうち attempt が非 COMPLETED のものだけを返す（未取得は無視）。
    """
    sr = getattr(scan_result, "scan_result", None) or scan_result
    out: list[str] = []
    for f in _scan_fields():
        attempt = getattr(sr, f, None)
        if attempt is not None and not _completed(attempt):
            out.append(f)
    return out


def _protocol_accepted(attempt: Any) -> bool:
    """cipher-suites の attempt が「そのプロトコルで 1 つ以上受理」かを判定する。"""
    if not _completed(attempt):
        return False
    try:
        return bool(getattr(getattr(attempt, "result", None), "accepted_cipher_suites", None))
    except Exception:
        return False


# (scan_result フィールド名, 表示ラベル, severity)。SSLv2/v3 は high、TLS1.0/1.1 は medium。
_WEAK_PROTOCOLS = (
    ("ssl_2_0_cipher_suites", "SSLv2", "high"),
    ("ssl_3_0_cipher_suites", "SSLv3", "high"),
    ("tls_1_0_cipher_suites", "TLS 1.0", "medium"),
    ("tls_1_1_cipher_suites", "TLS 1.1", "medium"),
)


# issue kind → CVSS v3.1 (score, vector)。severity バケツ一律ではなく、検出した脆弱性ごとの
# 実 impact を反映する（Codex #158）。score は対応 vector から計算される基本値で自己整合する。
#   - Heartbleed: メモリ over-read による機密性喪失のみ（完全性/可用性は無傷）→ C:H/I:N/A:N, AC:L。
#   - CCS Injection: MITM による鍵材料奪取で復号＋改ざん → C:H/I:H/A:N, AC:H。
#   - ROBOT / 弱プロトコル受理: 記録トラフィックの復号/ダウングレード（機密性）→ C:H/I:N/A:N, AC:H。
_KIND_CVSS: dict[str, tuple[float, str]] = {
    "heartbleed":    (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "ccs_injection": (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "robot":         (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "weak_protocol": (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}


def cvss_for_issue(kind: str) -> tuple[float, str]:
    """TLS issue の kind に対応する CVSS v3.1 (score, vector) を返す（純粋）。

    impact metric を脆弱性ごとに割り当てる（Heartbleed は機密性のみ＝I:N 等）。未知 kind は
    機密性のみの保守値（5.9）へフォールバックし、根拠の無い I:H を出さない。
    """
    return _KIND_CVSS.get(kind, (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"))


def extract_tls_issues(scan_result: Any) -> list[dict]:
    """sslyze の結果から TLS の設定不備 issue 一覧を作る（防御的・純粋）。

    ``scan_result`` は sslyze の ``ServerScanResult`` か、その ``scan_result``
    （``AllScanCommandsAttempts``）のいずれでもよい。各 issue は
    ``{"kind","label","severity","detail"}``。属性の欠落/例外時はその項目を黙って飛ばす
    （sslyze の版差・部分失敗でクラッシュしない）。
    """
    sr = getattr(scan_result, "scan_result", None) or scan_result
    issues: list[dict] = []

    for field, label, severity in _WEAK_PROTOCOLS:
        if _protocol_accepted(getattr(sr, field, None)):
            issues.append({
                "kind": "weak_protocol", "label": label, "severity": severity,
                "detail": f"{label} が受理されます（無効化を推奨）。",
            })

    hb = getattr(sr, "heartbleed", None)
    if _completed(hb) and getattr(getattr(hb, "result", None), "is_vulnerable_to_heartbleed", False):
        issues.append({"kind": "heartbleed", "label": "Heartbleed", "severity": "critical",
                       "detail": "Heartbleed (CVE-2014-0160) に脆弱です。"})

    ccs = getattr(sr, "openssl_ccs_injection", None)
    if _completed(ccs) and getattr(getattr(ccs, "result", None), "is_vulnerable_to_ccs_injection", False):
        issues.append({"kind": "ccs_injection", "label": "CCS Injection", "severity": "high",
                       "detail": "OpenSSL CCS Injection (CVE-2014-0224) に脆弱です。"})

    robot = getattr(sr, "robot", None)
    if _completed(robot):
        rr = getattr(getattr(robot, "result", None), "robot_result", None)
        # sslyze の enum は VULNERABLE_* / NOT_VULNERABLE_* なので startswith で判定
        # （"NOT_VULNERABLE" を substring 一致で拾わない）。
        if rr is not None and getattr(rr, "name", "").startswith("VULNERABLE"):
            issues.append({"kind": "robot", "label": "ROBOT", "severity": "high",
                           "detail": "ROBOT 攻撃に脆弱な可能性があります。"})

    return issues


def run_sslyze_scan(hostname: str, port: int = 443, timeout: float = 20.0) -> Optional[Any]:
    """対象ホストへ sslyze スキャンを実行して ServerScanResult を返す（同期・graceful）。

    非同期スキャナからは ``asyncio.to_thread`` 経由で呼ぶ想定。sslyze 未導入・接続不能・
    スキャン失敗はすべて ``None``（例外を投げない）。外部へデータ送信はしない。
    """
    if not hostname:
        return None
    try:
        from sslyze import (
            Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand,
        )
    except Exception:
        return None
    try:
        commands = {
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.HEARTBLEED,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.ROBOT,
        }
        # network_timeout を反映させる（版差で失敗したら既定設定へフォールバック）。
        net_config = None
        try:
            from sslyze import ServerNetworkConfiguration
            net_config = ServerNetworkConfiguration(
                tls_server_name_indication=hostname,
                network_timeout=max(1, int(timeout)),
            )
        except Exception:
            net_config = None
        request_kwargs = {
            "server_location": ServerNetworkLocation(hostname=hostname, port=port),
            "scan_commands": commands,
        }
        if net_config is not None:
            request_kwargs["network_configuration"] = net_config
        request = ServerScanRequest(**request_kwargs)
        scanner = Scanner()
        scanner.queue_scans([request])
        for result in scanner.get_results():
            return result  # 1 ホストのみ
    except Exception:
        return None
    return None
