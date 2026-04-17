"""
Compliance Mapping
==================
検出された脆弱性タイプを PCI DSS v4.0 / OWASP ASVS 4.0 / OWASP Top10 2021 /
IPA (情報処理推進機構) のセキュリティ基準にマッピングするデータモジュール。

使い方:
    from wscan.compliance_map import get_refs
    refs = get_refs("sqli")
    # {"pci_dss": [...], "owasp_asvs": [...], "owasp_top10": [...], "ipa": [...]}
"""
from __future__ import annotations

COMPLIANCE_REFS: dict[str, dict[str, list[str]]] = {
    "sqli": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.2"],
        "owasp_asvs":  ["ASVS V5.3.4", "ASVS V5.3.5"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.1 SQLインジェクション"],
    },
    "sqli_auth_bypass": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §8.3.6"],
        "owasp_asvs":  ["ASVS V5.3.4", "ASVS V2.1.1"],
        "owasp_top10": ["A03:2021 Injection", "A07:2021 Identification and Authentication Failures"],
        "ipa":         ["IPA 1.1 SQLインジェクション"],
    },
    "xss": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.3.3"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.5 クロスサイト・スクリプティング"],
    },
    "dom_xss": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.3.3", "ASVS V5.2.5"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.5 クロスサイト・スクリプティング"],
    },
    "stored_xss": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.3.3", "ASVS V5.1.3"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.5 クロスサイト・スクリプティング"],
    },
    "os": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.1"],
        "owasp_asvs":  ["ASVS V5.3.8"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.3 OSコマンド・インジェクション"],
    },
    "ssti": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.3.4"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.1 インジェクション (テンプレート)"],
    },
    "path_traversal": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.1"],
        "owasp_asvs":  ["ASVS V12.3.1", "ASVS V12.3.2"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 1.4 ディレクトリ・トラバーサル"],
    },
    "open_redirect": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.1.5"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 1.7 オープンリダイレクト"],
    },
    "csrf": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V4.2.2", "ASVS V13.2.3"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 1.6 CSRF (クロスサイト・リクエスト・フォージェリ)"],
    },
    "cors": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V14.4.7", "ASVS V14.5.3"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA セキュリティ実装チェックリスト オリジン検証"],
    },
    "header_injection": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.3.2"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.8 HTTPヘッダ・インジェクション"],
    },
    "mail_header": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.3.2"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.9 メールヘッダ・インジェクション"],
    },
    "clickjacking": {
        "pci_dss":     ["PCI DSS v4.0 §6.4.3"],
        "owasp_asvs":  ["ASVS V14.4.3"],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA セキュリティ実装チェックリスト クリックジャッキング"],
    },
    "session": {
        "pci_dss":     ["PCI DSS v4.0 §8.2.3", "PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V3.2.1", "ASVS V3.3.1", "ASVS V3.4.1"],
        "owasp_top10": ["A07:2021 Identification and Authentication Failures"],
        "ipa":         ["IPA セキュリティ実装チェックリスト セッション管理"],
    },
    "privesc_unauth": {
        "pci_dss":     ["PCI DSS v4.0 §7.2.1", "PCI DSS v4.0 §7.3.1"],
        "owasp_asvs":  ["ASVS V4.1.1", "ASVS V4.1.2"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 2.1 認可・アクセス制御"],
    },
    "privesc_vertical": {
        "pci_dss":     ["PCI DSS v4.0 §7.2.1"],
        "owasp_asvs":  ["ASVS V4.1.3", "ASVS V4.2.1"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 2.1 認可・アクセス制御"],
    },
    "privesc_horizontal": {
        "pci_dss":     ["PCI DSS v4.0 §7.2.1"],
        "owasp_asvs":  ["ASVS V4.1.3", "ASVS V4.2.1"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 2.1 認可・アクセス制御 (IDOR)"],
    },
    "privesc_param_idor": {
        "pci_dss":     ["PCI DSS v4.0 §7.2.1"],
        "owasp_asvs":  ["ASVS V4.2.1"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 2.1 認可・アクセス制御 (IDOR)"],
    },
    "privesc_cross_acct": {
        "pci_dss":     ["PCI DSS v4.0 §7.2.1"],
        "owasp_asvs":  ["ASVS V4.2.1"],
        "owasp_top10": ["A01:2021 Broken Access Control"],
        "ipa":         ["IPA 2.1 認可・アクセス制御"],
    },
    "info_disclosure": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §3.4.1"],
        "owasp_asvs":  ["ASVS V8.3.1", "ASVS V14.3.3"],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA セキュリティ実装チェックリスト エラー処理"],
    },
    "host_header": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.3.2"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.8 HTTPヘッダ・インジェクション"],
    },
    "security_headers": {
        "pci_dss":     ["PCI DSS v4.0 §6.4.3", "PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V14.4.1", "ASVS V14.4.3", "ASVS V14.4.4"],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA セキュリティ実装チェックリスト HTTPセキュリティヘッダ"],
    },
    "nosql": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.2"],
        "owasp_asvs":  ["ASVS V5.3.4", "ASVS V5.3.5"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.1 インジェクション (NoSQL)"],
    },
    "deserialization": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.1"],
        "owasp_asvs":  ["ASVS V1.14.5", "ASVS V5.5.1"],
        "owasp_top10": ["A08:2021 Software and Data Integrity Failures"],
        "ipa":         ["IPA 安全でないデシリアライゼーション"],
    },
    "request_smuggling": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V14.5.1"],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA HTTPリクエストスマグリング"],
    },
    "ssrf": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §1.3.2"],
        "owasp_asvs":  ["ASVS V10.3.2", "ASVS V12.6.1"],
        "owasp_top10": ["A10:2021 Server-Side Request Forgery"],
        "ipa":         ["IPA サーバーサイドリクエストフォージェリ"],
    },
    "graphql_introspection": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V13.4.1"],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA API設計 情報公開制限"],
    },
    "graphql_injection": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.2"],
        "owasp_asvs":  ["ASVS V5.3.4", "ASVS V13.4.1"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA 1.1 インジェクション (GraphQL)"],
    },
    "graphql_batch": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V13.4.1"],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA API設計 レート制限"],
    },
    "graphql_sensitive": {
        "pci_dss":     ["PCI DSS v4.0 §3.4.1", "PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V8.3.1", "ASVS V13.4.1"],
        "owasp_top10": ["A02:2021 Cryptographic Failures"],
        "ipa":         ["IPA API設計 機密情報露出"],
    },
    "jwt_alg_none": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §8.3.9"],
        "owasp_asvs":  ["ASVS V3.5.2", "ASVS V3.5.3"],
        "owasp_top10": ["A02:2021 Cryptographic Failures"],
        "ipa":         ["IPA JWT 署名検証不備"],
    },
    "jwt_weak_secret": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §8.3.9"],
        "owasp_asvs":  ["ASVS V3.5.2"],
        "owasp_top10": ["A02:2021 Cryptographic Failures"],
        "ipa":         ["IPA JWT 弱い署名鍵"],
    },
    "jwt_kid_injection": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.2"],
        "owasp_asvs":  ["ASVS V3.5.2", "ASVS V5.3.4"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA JWT kidパラメータインジェクション"],
    },
    "jwt_payload_tamper": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §8.3.9"],
        "owasp_asvs":  ["ASVS V3.5.2", "ASVS V3.5.3"],
        "owasp_top10": ["A07:2021 Identification and Authentication Failures"],
        "ipa":         ["IPA JWT ペイロード改ざん"],
    },
    "jwt_no_expiry": {
        "pci_dss":     ["PCI DSS v4.0 §8.2.3"],
        "owasp_asvs":  ["ASVS V3.3.1"],
        "owasp_top10": ["A07:2021 Identification and Authentication Failures"],
        "ipa":         ["IPA JWT 有効期限なし"],
    },
    "jwt_sensitive_data": {
        "pci_dss":     ["PCI DSS v4.0 §3.4.1"],
        "owasp_asvs":  ["ASVS V8.3.1"],
        "owasp_top10": ["A02:2021 Cryptographic Failures"],
        "ipa":         ["IPA JWT 機密情報埋込み"],
    },
    "cms": {
        "pci_dss":     ["PCI DSS v4.0 §6.3.3", "PCI DSS v4.0 §12.3.2"],
        "owasp_asvs":  ["ASVS V14.2.1"],
        "owasp_top10": ["A06:2021 Vulnerable and Outdated Components"],
        "ipa":         ["IPA CMS 既知の脆弱性"],
    },
    "xxe": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V5.5.2"],
        "owasp_top10": ["A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA XML外部エンティティ参照 (XXE)"],
    },
    "ldap": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.2"],
        "owasp_asvs":  ["ASVS V5.3.4"],
        "owasp_top10": ["A03:2021 Injection"],
        "ipa":         ["IPA LDAPインジェクション"],
    },
    "file_upload": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4", "PCI DSS v4.0 §6.3.1"],
        "owasp_asvs":  ["ASVS V12.2.1", "ASVS V12.3.1"],
        "owasp_top10": ["A04:2021 Insecure Design", "A05:2021 Security Misconfiguration"],
        "ipa":         ["IPA ファイルアップロード不備"],
    },
    "race_condition": {
        "pci_dss":     ["PCI DSS v4.0 §6.2.4"],
        "owasp_asvs":  ["ASVS V11.1.6"],
        "owasp_top10": ["A04:2021 Insecure Design"],
        "ipa":         ["IPA 競合状態 (TOCTOU)"],
    },
}


def get_refs(check_type: str) -> dict[str, list[str]]:
    """
    check_type に対応するコンプライアンス参照を返す。
    完全一致がなければ check_type の最初の部分 (アンダースコア前) でフォールバック。

    Parameters
    ----------
    check_type : "sqli", "xss", "jwt_alg_none" など

    Returns
    -------
    {"pci_dss": [...], "owasp_asvs": [...], "owasp_top10": [...], "ipa": [...]}
    空の場合は {} を返す。
    """
    if check_type in COMPLIANCE_REFS:
        return COMPLIANCE_REFS[check_type]
    # prefix fallback: jwt_alg_none → jwt
    base = check_type.split("_")[0]
    return COMPLIANCE_REFS.get(base, {})
