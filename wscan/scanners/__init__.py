"""WScan Scanner Modules

Central registry for all vulnerability scanners. `engine.py` imports `SCANNERS`
to build its scanner map so that the registry stays in one place.
"""
from .clickjacking import ClickjackingScanner
from .cms import CmsScanner
from .cors import CORSScanner
from .csrf import CSRFScanner
from .deserialization import DeserializationScanner
from .dom_xss import DOMXSSScanner
from .graphql import GraphQLScanner
from .header_injection import HeaderInjectionScanner
from .host_header import HostHeaderScanner
from .info_disclosure import InfoDisclosureScanner
from .js_static import JsStaticScanner
from .jwt_scanner import JWTScanner
from .mail_header import MailHeaderInjectionScanner
from .nosql_injection import NoSQLInjectionScanner
from .open_redirect import OpenRedirectScanner
from .os_injection import OSInjectionScanner
from .path_traversal import PathTraversalScanner
from .privesc import PrivEscScanner
from .request_smuggling import RequestSmugglingScanner
from .security_headers import SecurityHeadersScanner
from .session import SessionScanner
from .sqli import SQLiScanner
from .ssrf import SSRFScanner
from .ssti import SSTIScanner
from .stored_xss import StoredXSSScanner
from .xss import XSSScanner
from .xxe import XXEScanner
from .ldap_injection import LDAPScanner
from .file_upload import FileUploadScanner
from .race_condition import RaceConditionScanner
from .secret_leak import SecretLeakScanner
from .sri import SRIScanner
from .websocket import WebSocketScanner


# check-type string → scanner class
SCANNERS: dict[str, type] = {
    "sqli":              SQLiScanner,
    "xss":               XSSScanner,
    "dom_xss":           DOMXSSScanner,
    "os":                OSInjectionScanner,
    "ssti":              SSTIScanner,
    "path_traversal":    PathTraversalScanner,
    "csrf":              CSRFScanner,
    "header_injection":  HeaderInjectionScanner,
    # "mail_header" は意図的に無効化（レジストリから除外）。
    # メールヘッダインジェクションの確証には注入された Cc/Bcc 宛メールを
    # 実際に受信・観測する必要があり、ブラウザ経由の黒box スキャンでは
    #   (1) <input> の value sanitization で CR/LF が除去され注入が成立しない
    #   (2) 外向きメールの中身はスキャナから観測できない
    # ため誤検知・取りこぼしが避けられない。OOB メール受信箱 (自前 IMAP /
    # collaborator ドメイン) を整備して初めて実用的な検査が可能になる。
    # 実装 (MailHeaderInjectionScanner) は将来の再有効化のため残置している。
    # "mail_header":       MailHeaderInjectionScanner,
    "open_redirect":     OpenRedirectScanner,
    "clickjacking":      ClickjackingScanner,
    "session":           SessionScanner,
    "privesc":           PrivEscScanner,
    "stored_xss":        StoredXSSScanner,
    "cors":              CORSScanner,
    "info_disclosure":   InfoDisclosureScanner,
    "host_header":       HostHeaderScanner,
    "security_headers":  SecurityHeadersScanner,
    "nosql":             NoSQLInjectionScanner,
    "deserialization":   DeserializationScanner,
    "request_smuggling": RequestSmugglingScanner,
    "ssrf":              SSRFScanner,
    "graphql":           GraphQLScanner,
    "jwt":               JWTScanner,
    "cms":               CmsScanner,
    "xxe":               XXEScanner,
    "ldap":              LDAPScanner,
    "file_upload":       FileUploadScanner,
    "race_condition":    RaceConditionScanner,
    "websocket":         WebSocketScanner,
    "secret_leak":       SecretLeakScanner,
    "sri":               SRIScanner,
    "js_static":         JsStaticScanner,
}


__all__ = [
    "SCANNERS",
    "ClickjackingScanner", "CmsScanner", "CORSScanner", "CSRFScanner",
    "DeserializationScanner", "DOMXSSScanner", "GraphQLScanner",
    "HeaderInjectionScanner", "HostHeaderScanner", "InfoDisclosureScanner",
    "JWTScanner", "MailHeaderInjectionScanner", "NoSQLInjectionScanner",
    "OpenRedirectScanner", "OSInjectionScanner", "PathTraversalScanner",
    "PrivEscScanner", "RequestSmugglingScanner", "SecurityHeadersScanner",
    "SessionScanner", "SQLiScanner", "SSRFScanner", "SSTIScanner",
    "StoredXSSScanner", "XSSScanner",
    "XXEScanner", "LDAPScanner", "FileUploadScanner", "RaceConditionScanner",
    "WebSocketScanner", "SecretLeakScanner", "SRIScanner", "JsStaticScanner",
]
