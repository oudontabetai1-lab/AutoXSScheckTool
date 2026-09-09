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
        request = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=hostname, port=port),
            scan_commands=commands,
        )
        scanner = Scanner()
        scanner.queue_scans([request])
        for result in scanner.get_results():
            return result  # 1 ホストのみ
    except Exception:
        return None
    return None
