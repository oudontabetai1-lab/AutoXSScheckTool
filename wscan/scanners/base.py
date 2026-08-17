"""
Base Scanner Class
Provides common utilities for all vulnerability scanners.
"""
import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

import httpx

from wscan.injection_point import (
    InjectionPoint,
    pointer_set_copy,
    redact_body_except,
    redact_known_secrets,
    sibling_string_values,
)

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# CVSS 3.1 base score lookup table: check_type → (vector_string, numeric_score)
# Vectors use worst-case assumptions for web scanner context.
_CVSS_TABLE: dict[str, tuple[str, float]] = {
    "sqli":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "sqli_auth_bypass":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "xss":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "dom_xss":           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "os":                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "ssti":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "path_traversal":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "open_redirect":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  6.1),
    "csrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",  6.5),
    "header_injection":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  5.3),
    "mail_header":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  5.3),
    "clickjacking":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  4.3),
    "session":           ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  7.4),
    "privesc_unauth":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  9.1),
    "privesc_vertical":  ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "privesc_horizontal":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    # V-1〜V-9 new scanners
    "stored_xss":        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",  9.6),
    "cors":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",  7.4),
    "info_disclosure":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "host_header":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  5.4),
    "security_headers":  ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  3.1),
    "nosql":             ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  9.1),
    "deserialization":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "request_smuggling": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",  8.7),
    "ssrf":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.8),
    # ② GraphQL scanner
    "graphql_introspection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "graphql_injection":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "graphql_batch":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  5.3),
    "graphql_sensitive":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "graphql_dos":           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  7.5),
    # ④ JWT scanner
    "jwt_alg_none":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_weak_secret":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_kid_injection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "jwt_payload_tamper":("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "jwt_no_expiry":     ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    "jwt_sensitive_data":("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  5.3),
    # A: Additional privesc check types
    "privesc_param_idor":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  6.5),
    "privesc_cross_acct":("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "privesc_action":    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "privesc_bypass":    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  8.1),
    # Phase-4 new scanners
    "xxe":               ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "ldap":              ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    "file_upload":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "race_condition":    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",  6.8),
    "websocket":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",  9.6),
    # 静的 JS 監査（DOM XSS 前段階）。実行確証前のため XSS よりやや低め。
    "js_static":         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "js_dangerous_sink": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    # 新クラス
    "prototype_pollution":        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "prototype_pollution_dom":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",  8.8),
    "prototype_pollution_server": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "cache_poisoning":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",  8.1),
    "cache_deception":   ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",  7.4),
    "mass_assignment":   ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
}


def _cvss_for(check_type: str) -> tuple[str, float]:
    """Return (vector, score) for a check type, or empty defaults."""
    base = check_type.split("_")[0] if "_" in check_type else check_type
    return _CVSS_TABLE.get(check_type) or _CVSS_TABLE.get(base, ("", 0.0))


# spec（OpenAPI/Postman）由来のテンプレヘッダで上書きしてはいけない認証情報ヘッダ。
# 利用者の --header / トークン更新（auth_headers 由来）が常に優先される。
_CREDENTIAL_HEADERS = frozenset({
    "authorization", "x-api-key", "x-auth-token", "x-access-token",
    "proxy-authorization", "cookie",
})


def merge_template_headers(base: dict, tmpl_headers: dict) -> dict:
    """auth_headers ベースに spec テンプレヘッダを重ねる（純粋）。

    認証情報ヘッダ（``_CREDENTIAL_HEADERS``）が ``base`` に既にあれば、テンプレの値
    （spec/Postman の Authorization/API-key の example・default）で上書きしない。
    利用者が ``--header`` で渡した実値や更新トークンを spec のプレースホルダで潰すと、
    保護 API への直接 httpx 検査（mass_assignment / server-side proto）が未認証になり
    脆弱性を取りこぼすため。認証情報以外（必須の X-API-Version/tenant 等）はテンプレ値
    で上書きしてよい（operation 固有の必須ヘッダを補完する）。
    """
    out = dict(base or {})
    present = {k.lower() for k in out}
    for k, v in (tmpl_headers or {}).items():
        if k.lower() in _CREDENTIAL_HEADERS and k.lower() in present:
            continue
        out[k] = v
    return out


def _redact_json_evidence_pair(pair: dict, injection_pointer: str) -> dict:
    """json_body Finding 用に証跡 pair を伏せた**コピー**を返す（純粋・検出には非使用）。

    検出は生 pair で既に完了している前提。ここでは永続/配信される Finding.request/response
    から、テンプレの兄弟秘匿(request body・エコーされた response 本文)と認証ヘッダ値を伏せる。
    注入 pointer の値は残す（再現時にどの pointer に何を入れたか読めるように）。
    - request.post_data: 兄弟をマスク、注入 pointer の値のみ残す。
    - request/response.headers: テンプレ由来やサーバ発行で ``_SENSITIVE_HEADERS`` 未登録の
      X-Access-Token 等も伏せるため、双方のヘッダを ``_CREDENTIAL_HEADERS`` で判定してマスク。
    - response.body: エコーされた既知の兄弟秘匿を符号化違いも含め伏せる。
    """
    req = dict(pair.get("request", {}) or {})
    resp = dict(pair.get("response", {}) or {})
    raw_post = req.get("post_data")
    parsed = None
    if isinstance(raw_post, str) and raw_post:
        try:
            parsed = json.loads(raw_post)
        except ValueError:
            parsed = None
    secrets: list[str] = []
    if isinstance(parsed, (dict, list)):
        secrets = sibling_string_values(parsed, injection_pointer)
        req["post_data"] = json.dumps(redact_body_except(parsed, injection_pointer))
    # request/response 双方の認証ヘッダ値をマスク（サーバが X-Access-Token 等を応答で
    # 返す場合も to_dict→checkpoint/report/monitor へ流さない）。
    if isinstance(req.get("headers"), dict):
        req["headers"] = _mask_credential_headers(req["headers"])
    if isinstance(resp.get("headers"), dict):
        resp["headers"] = _mask_credential_headers(resp["headers"])
    body = resp.get("body")
    if isinstance(body, str) and secrets:
        resp["body"] = redact_known_secrets(body, secrets)
    return {**pair, "request": req, "response": resp}


def _mask_credential_headers(headers: dict) -> dict:
    """``_CREDENTIAL_HEADERS`` に該当するヘッダ値を伏せた新 dict を返す（純粋）。"""
    return {
        k: ("***" if str(k).lower() in _CREDENTIAL_HEADERS else v)
        for k, v in headers.items()
    }


def finding_dedup_key(
    check_type: str,
    url: str,
    field_name: str,
    evidence_type: str = "",
) -> tuple[str, str, str, str]:
    """
    Deduplicate exact evidence, not entire inputs.

    A single parameter can legitimately produce distinct vulnerability evidence
    (for example SQL error disclosure and authentication bypass).  Treating the
    whole (url, field, check) tuple as duplicate loses those findings.
    """
    return (url, field_name, check_type, evidence_type or check_type)


def _augment_dedup_key(
    base: tuple,
    injection_location: str,
    injection_method: str,
    injection_pointer: str,
) -> tuple:
    """JSON body 注入点の dedup identity を method+pointer で拡張する（純粋）。

    同一 leaf 名(例 /profile/id と /billing/id が共に field_name="id")でも別入力
    なので取りこぼさない。form/url_param は base のまま(4-tuple)。record_finding・
    finding_dedup_key_for(engine の _record_finding/_init_checkpoint 経由)の**全 dedup
    地点で同一キー**になるよう、この 1 箇所に集約する。
    """
    if injection_location == "json_body":
        return base + (injection_method, injection_pointer)
    return base


def finding_dedup_key_for(finding: "Finding") -> tuple:
    return _augment_dedup_key(
        finding_dedup_key(
            finding.check_type,
            finding.url,
            finding.field_name,
            finding.evidence_type,
        ),
        getattr(finding, "injection_location", ""),
        getattr(finding, "injection_method", ""),
        getattr(finding, "injection_pointer", ""),
    )


@dataclass
class Finding:
    """A security vulnerability finding."""
    check_type: str          # sqli, xss, os, etc.
    severity: str            # critical, high, medium, low, info
    url: str
    field_name: str
    payload: str
    evidence: str            # Description of what triggered the finding
    request: dict = field(default_factory=dict)
    response: dict = field(default_factory=dict)
    screenshot_b64: str = ""
    dialog_confirmed: bool = False   # True when JS alert() was actually triggered
    dialog_message: str = ""         # The alert message that appeared
    timestamp: float = field(default_factory=time.time)
    verified: bool = True            # False = could not reproduce on second attempt
    verification_note: str = ""      # Reason when verified=False
    confidence: str = "tentative"   # "confirmed" | "likely" | "tentative"
    evidence_type: str = ""          # Structured signal, e.g. xss_dialog, sqli_error
    evidence_details: dict = field(default_factory=dict)
    reproduction_steps: list[str] = field(default_factory=list)
    source: str = "scanner"          # "scanner" | "agent"
    agent_verified: bool = False      # Agent 発見を決定論スキャナでも再現できたか
    injection_location: str = ""       # 空文字は旧来または不明の注入経路
    injection_pointer: str = ""        # JSON body 内の JSON Pointer
    injection_method: str = ""         # JSON body 送信時の HTTP メソッド
    injection_template_id: str = ""    # 秘匿値を持たないテンプレート識別子
    injection_form_index: int = 0       # form 注入点の index（段階5b で記録）
    # reproduced | assumed | unreproduced | skipped。既定は None sentinel で、__post_init__ が
    # 「新規 finding は必ず非空 state」を保証する（空文字は from_dict の旧 Finding 専用に予約）。
    verification_state: str = None

    def __post_init__(self):
        # record_finding を通らない直接構築（ChainScanner/GraphQL/JWT/privesc/websocket 等）も
        # 含め、生成境界で一元的に既定 state を与える（whack-a-mole 防止）。dialog 発火=scan 時点で
        # 実行確証=reproduced。それ以外=assumed（_phase_verify を通る verifiable finding は後で
        # reproduced/unreproduced/skipped に上書き）。from_dict は空文字を明示的に渡すため（旧
        # Finding）ここで上書きされず、"" が旧 Finding 専用として保たれる。
        if self.verification_state is None:
            self.verification_state = "reproduced" if self.dialog_confirmed else "assumed"

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """``to_dict`` 由来の dict から Finding を復元する（再開スキャン用）。

        ``to_dict`` は ``cvss_*`` 等の算出値を足し、response.body を落とすため
        完全な往復ではない。レポート継続に必要なフィールドのみ復元する。
        """
        resp = dict(data.get("response", {}) or {})
        if data.get("response_body_excerpt") and "body" not in resp:
            resp["body"] = data.get("response_body_excerpt", "")
        return cls(
            check_type=data.get("check_type", ""),
            severity=data.get("severity", "medium"),
            url=data.get("url", ""),
            field_name=data.get("field_name", ""),
            payload=data.get("payload", ""),
            evidence=data.get("evidence", ""),
            request=dict(data.get("request", {}) or {}),
            response=resp,
            screenshot_b64=data.get("screenshot_b64", ""),
            dialog_confirmed=bool(data.get("dialog_confirmed", False)),
            dialog_message=data.get("dialog_message", ""),
            timestamp=data.get("timestamp", time.time()),
            verified=bool(data.get("verified", True)),
            verification_note=data.get("verification_note", ""),
            verification_state=data.get("verification_state", ""),
            confidence=data.get("confidence", "tentative"),
            evidence_type=data.get("evidence_type", ""),
            evidence_details=dict(data.get("evidence_details", {}) or {}),
            reproduction_steps=list(data.get("reproduction_steps", []) or []),
            source=data.get("source", "scanner"),
            agent_verified=bool(data.get("agent_verified", False)),
            injection_location=data.get("injection_location", ""),
            # 欠落キーは None(sentinel)にして「明示的な空文字ルート pointer」と区別する。
            # to_dict は常に書き出すので正規の checkpoint では常に存在するが、json_body を
            # 名乗りつつ pointer キーを欠く不完全 provenance（手編集/異版）は None のまま
            # resolver で unexecutable 扱いにし、whole-body 再送で誤って未確証化しない。
            injection_pointer=data.get("injection_pointer"),
            injection_method=data.get("injection_method", ""),
            injection_template_id=data.get("injection_template_id", ""),
            injection_form_index=int(data.get("injection_form_index", 0) or 0),
        )

    @property
    def cvss_vector(self) -> str:
        return _cvss_for(self.check_type)[0]

    @property
    def cvss_score(self) -> float:
        return _cvss_for(self.check_type)[1]

    def to_dict(self) -> dict:
        from wscan.compliance_map import get_refs
        from wscan.request_logger import _redact_headers

        request = dict(self.request)
        if "headers" in request:
            request["headers"] = _redact_headers(request["headers"])
        response = {k: v for k, v in self.response.items() if k != "body"}
        if "headers" in response:
            response["headers"] = _redact_headers(response["headers"])

        return {
            "check_type": self.check_type,
            "severity": self.severity,
            "url": self.url,
            "field_name": self.field_name,
            "payload": self.payload,
            "evidence": self.evidence,
            "request": request,
            "response": response,
            "response_body_excerpt": (self.response.get("body", "") or "")[:500],
            "screenshot_b64": self.screenshot_b64,
            "dialog_confirmed": self.dialog_confirmed,
            "dialog_message": self.dialog_message,
            "timestamp": self.timestamp,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "verified": self.verified,
            "verification_note": self.verification_note,
            "verification_state": self.verification_state,
            "confidence": self.confidence,
            "evidence_type": self.evidence_type,
            "evidence_details": self.evidence_details,
            "reproduction_steps": self.reproduction_steps,
            "source": self.source,
            "agent_verified": self.agent_verified,
            "injection_location": self.injection_location,
            "injection_pointer": self.injection_pointer,
            "injection_method": self.injection_method,
            "injection_template_id": self.injection_template_id,
            "injection_form_index": self.injection_form_index,
            "compliance_refs": get_refs(self.check_type),
        }


class ProvenanceError(ValueError):
    """Finding の非空 provenance が不正または不足している。"""


def injection_point_from_finding(finding: Finding) -> Optional[InjectionPoint]:
    """Finding の provenance から注入点を復元する。空 location は旧 Finding として扱う。"""
    location = finding.injection_location
    if location == "":
        return None
    if location == "form":
        return InjectionPoint.for_form(
            finding.url,
            finding.field_name,
            finding.injection_form_index,
        )
    if location == "url_param":
        return InjectionPoint.for_url_param(finding.url, finding.field_name)
    if location == "json_body":
        # 空文字は RFC 6901 の**ルート pointer**（ドキュメント全体への注入）で valid。
        # `parse_pointer("")` は [] を返し `pointer_set_copy(doc, "", payload)` は
        # body 全体を payload に置換する（whole-body JSON 注入）。空を一律 corrupt と
        # 誤判定すると verify で再送されず未検証のまま確証扱いになる。malformed は
        # 非空で '/' 始まりでない場合に parse_pointer が ValueError を投げる分だけ。
        # json_body の再送は HTTP replay なので **非空の method が必須**。欠落（from_dict が
        # "" に既定）・明示的 "" は `"".upper()` で例外にならず「実行可能」な IP に化けるが、
        # 実際には送信不能で空応答→未確証誤判定になる。executability の前提として method が
        # 非空 str であることを明示検査し、満たさなければ corrupt（unexecutable）へ倒す。
        # （null/非文字列 method は下の except でも捕えるが、"" は例外にならないためここで弾く。）
        if not isinstance(finding.injection_method, str) or not finding.injection_method:
            raise ProvenanceError(
                "json_body provenance の HTTP method が欠落/空です: "
                f"{finding.injection_method!r}"
            )
        # 上記以外の不完全 provenance（pointer が null・キー欠落=None sentinel・その他の
        # 非文字列）は for_json_body 内で parse_pointer(pointer) が ValueError/AttributeError/
        # TypeError を投げる。フィールド毎に型検査を積むと後追い（whack-a-mole）になるので、
        # **復元境界でまとめて捕え**「壊れた provenance = unexecutable」へ一本化する。これにより
        # 1 件の破損 entry が verify 経路へ非 ProvenanceError を漏らして _phase_verify 全体を
        # 止める事故を防ぐ。明示的に格納された "" ルート pointer は valid（欠落=None sentinel
        # とは区別して復元される）。
        try:
            return InjectionPoint.for_json_body(
                finding.injection_method,
                finding.url,
                finding.injection_pointer,
                display_name=finding.field_name,
                template_id=finding.injection_template_id,
            )
        except (ValueError, AttributeError, TypeError) as exc:
            raise ProvenanceError(
                f"json_body provenance を復元できません: {exc!r}"
            ) from exc
    raise ProvenanceError(f"未知の injection_location です: {location!r}")


class BaseScanner(ABC):
    """Base class for all vulnerability scanners."""

    CHECK_TYPE = "base"
    SEVERITY = "medium"
    SUPPORTS_JSON_BODY = False

    def __init__(self, engine: "ScanEngine"):
        self.engine = engine
        self.browser = engine.browser
        self.monitor = engine.monitor
        self.payload_gen = engine.payload_gen
        self.findings: list[Finding] = []

    def _record_scan_note(self, note: str) -> None:
        """検出力に関わる出来事を ``engine.wave_errors`` に記録する（観測可能化）。

        monitor 非依存・テストで観測可能。記録のみで scan ループの挙動は変えない。
        wave 失敗（evolution/mutation/probe）や baseline 取得不能による finding 抑止
        など「黙って検出力が落ちる」事象を残し、誤検知ゼロ方針の副作用（見逃し）を
        後から追えるようにする。
        """
        errors = getattr(self.engine, "wave_errors", None)
        if errors is None:
            errors = []
            try:
                self.engine.wave_errors = errors
            except Exception:
                return
        errors.append(note)

    def _note_wave_degradation(self, wave: str, exc: Exception) -> None:
        """payload 強化 wave（evolution/mutation）の失敗を *観測可能* にする。

        これらの wave は加算的・例外保護が設計上の不変条件で、失敗しても scan
        ループを壊してはならない。だが ``except: return []`` で握りつぶすと
        検出力の低下（blind/time 系の喪失など）に誰も気づけない。ここでエンジンに
        記録だけ残し（monitor 非依存・テストで観測可能）、従来どおり空 list へ
        フォールバックする。ループ挙動は一切変えない。
        """
        self._record_scan_note(f"{wave}:{self.CHECK_TYPE}: {type(exc).__name__}: {exc}")

    @abstractmethod
    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """Scan a single input field for vulnerabilities."""
        ...

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        """段階5 の一時互換アダプタ。既存 scan_field へ委譲し挙動を変えない。

        段階5b で各スキャナが本メソッドを override し、ip 駆動 dispatch へ移行する。
        """
        return await self.scan_field(
            ip.url,
            ip.form_index,
            field,
            ip.legacy_is_url_param(),
        )

    async def _apply_ip(
        self,
        ip: InjectionPoint,
        payload,
    ) -> tuple[str, dict]:
        """注入点の location に応じて既存 transport へ振り分ける。

        form/url_param は既存 ``_apply_payload`` へそのまま委譲し、json_body は
        capability を明示したスキャナだけ共有 transport を使う。未対応の JSON を
        form へ暗黙に落とさないことで tri-state を維持する。
        """
        if ip.location == "json_body":
            if not self.SUPPORTS_JSON_BODY:
                return "", {}
            return await self._apply_json_payload(ip, payload)
        return await self._apply_payload(
            ip.url,
            ip.form_index,
            ip.parameter_id,
            payload,
            ip.legacy_is_url_param(),
        )

    def _verify_injection_point(
        self,
        finding: "Finding",
        is_url_param: bool,
    ) -> Optional[InjectionPoint]:
        """verify の再送に使う注入点を復元する。

        非空の provenance は全 location で優先し、壊れていれば再送不能として None を返す。
        location が空の旧 Finding だけ、従来の URL クエリ推測へ fallback する。
        """
        try:
            ip = injection_point_from_finding(finding)
        except ProvenanceError:
            return None
        if ip is not None:
            return ip
        if is_url_param:
            return InjectionPoint.for_url_param(finding.url, finding.field_name)
        return InjectionPoint.for_form(finding.url, finding.field_name, 0)

    async def scan_page(self, url: str) -> list[Finding]:
        """
        Optional page-level check called once per URL, before per-field scanning.
        Override in scanners that inspect HTTP headers, cookies, or page structure
        (e.g. Clickjacking, Session, CSRF) rather than injecting payloads into fields.
        Default: returns empty list (no-op).
        """
        return []

    async def verify_finding(self, finding: Finding) -> Optional[bool]:
        """
        Scanner-specific reproduction check.

        Return True/False when the scanner can verify the finding, or None to
        let the engine use its generic fallback.
        """
        return None

    @property
    def sleep_factor(self) -> float:
        """Scaling factor for sleep durations (0.5 in CTF mode, 1.0 otherwise)."""
        return getattr(self.engine, "sleep_factor", 1.0)

    def auth_headers_for_url(
        self,
        url: str,
        extra: Optional[dict] = None,
        *,
        include_cookie: bool = True,
    ) -> dict:
        """Return engine authentication headers scoped to a request URL.

        Lightweight scanner test doubles created before URL-scoped headers do
        not expose ``headers_for_url``.  Keep those compatible while ensuring
        the real ScanEngine always reaches its URL-aware helper.
        """
        auth_headers = getattr(self.engine, "auth_headers", None)
        if not callable(auth_headers):
            return dict(extra or {})
        if hasattr(self.engine, "headers_for_url"):
            return auth_headers(
                extra,
                include_cookie=include_cookie,
                url=url,
            )
        return auth_headers(extra, include_cookie=include_cookie)

    async def log_payload_test(
        self, field_name: str, payload: str, check_type: str, url: str = ""
    ) -> None:
        """Record a tested payload to the audit log and (if present) the dashboard.

        Monitor-independent: writes to ``engine.request_logger`` so
        ``payloads.jsonl`` is produced even in ``--no-monitor`` / batch runs
        (where ``monitor`` is ``None``), then emits the live dashboard event
        only when a monitor is attached. The file write happens here — not in
        ``MonitorServer.emit_payload_test`` — so it is never skipped just
        because the dashboard is absent, and not duplicated when present.
        """
        # operator が停止(abort)を要求していたら、次の payload 投入前にここで中断する。
        # 全注入系 scanner が payload 投入直前に必ずこの helper を通す不変条件を利用し、
        # 1 payload 単位で abort を反映する（フィールド完了まで待たない即時停止）。
        # controller は attack 実行中のみ True を返す（検証フェーズは stop() 済みで無効）。
        controller = getattr(getattr(self, "engine", None), "controller", None)
        if controller is not None and controller.abort_requested():
            from wscan.intervention import AbortScan
            raise AbortScan("Scan aborted by operator")
        # engine/monitor が未配線でも壊れないようにする（baseline/verify などの再投入で
        # この helper を広く呼ぶため、stub 構築されたスキャナでも安全に no-op になる）。
        logger = getattr(getattr(self, "engine", None), "request_logger", None)
        if logger is not None:
            logger.log_payload(field_name, payload, check_type, url)
        monitor = getattr(self, "monitor", None)
        if monitor:
            await monitor.emit_payload_test(field_name, payload, check_type, url)

    async def get_payloads(self, field_name: str, url: str) -> list[str]:
        """Get payloads for this scanner's check type, sorted by learning data."""
        # Check per-task ContextVar override first (set by engine for parallel isolation),
        # fall back to the engine-level custom_payloads dict.
        from wscan.engine import _FIELD_PAYLOAD_OVERRIDES
        _overrides = _FIELD_PAYLOAD_OVERRIDES.get()
        _custom = (
            _overrides.get(self.CHECK_TYPE)
            if _overrides
            else self.engine.custom_payloads.get(self.CHECK_TYPE)
        )
        payloads = await self.payload_gen.generate(
            check_type=self.CHECK_TYPE,
            field_name=field_name,
            url=url,
            custom_payloads=_custom,
        )
        # A-3 / ⑩: re-order by historical success rate (domain-aware)
        learner = getattr(self.engine, "payload_learner", None)
        if learner and getattr(self.engine, "enable_payload_learning", True):
            from urllib.parse import urlparse as _up
            _domain = _up(getattr(self.engine, "target_url", "")).hostname or None
            payloads = learner.sort_payloads(self.CHECK_TYPE, payloads, domain=_domain)
        # Fast mode: cap payload count (highest-priority payloads are already first)
        cap = getattr(self.engine, "max_payloads", 0)
        if cap > 0:
            payloads = payloads[:cap]
        return payloads

    def check_response_for_patterns(self, body: str, patterns: list[str]) -> Optional[str]:
        """Check response body for any of the given regex patterns."""
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:200]
        return None

    def response_time_exceeded(self, pair: dict, threshold: float = 3.0) -> bool:
        """Check if response time suggests a time-based injection."""
        elapsed = self.response_elapsed(pair)
        return elapsed is not None and elapsed >= threshold

    def response_elapsed(self, pair: dict) -> Optional[float]:
        """応答の所要時間(秒)を返す。計測できなければ None。"""
        req = pair.get("request", {}) or {}
        resp = pair.get("response", {}) or {}
        req_ts = req.get("timestamp", 0)
        resp_ts = resp.get("timestamp", 0)
        if req_ts and resp_ts:
            return resp_ts - req_ts
        return None

    async def _apply_json_payload(
        self,
        ip: InjectionPoint,
        payload,
    ) -> tuple[str, dict]:
        """JSON body 注入点へ payload を送信し、応答本文と通信記録を返す。"""
        template = (
            getattr(self.engine, "injection_templates", {}) or {}
        ).get(ip.template_id)
        if not isinstance(template, dict):
            return "", {}

        try:
            url = template.get("url") or ip.url
            method = (template.get("method") or ip.method or "POST").upper()
            body = pointer_set_copy(
                template.get("json_body"),
                ip.parameter_id,
                payload,
            )
            post_data = json.dumps(body)
            content_type = template.get("content_type") or "application/json"
            headers = self.auth_headers_for_url(
                url,
                {"Content-Type": content_type},
            )
            headers = merge_template_headers(
                headers,
                template.get("headers") or {},
            )
            kwargs = {
                "timeout": getattr(self.engine, "timeout", 15),
                "follow_redirects": True,
                "headers": headers,
            }
            if hasattr(self.engine, "httpx_client_kwargs"):
                kwargs = self.engine.httpx_client_kwargs(**kwargs)
            elif getattr(self.engine, "proxy", ""):
                kwargs["proxy"] = self.engine.proxy
        except Exception:
            return "", {}

        # 監査ログ(payloads.jsonl / monitor)と abort 判定は**呼び出し側(scanner)が
        # _apply_ip の直前に log_payload_test で一元化**する（form/url_param の _apply_payload と同じ
        # 単層ログ）。ここで再度 log すると json 経路だけ二重記録・二重 dashboard イベントになり、
        # payloads.jsonl が送信リクエストと 1:1 対応しなくなるため、transport 側では log しない。
        # transport は**忠実**に振る舞う: source も pair も生応答を返す。検出（反射/エラー
        # 文字列/長さ差）は生本文で行う必要があり、兄弟値を先に伏せると短い共通値
        # （例 "a"/"admin"）が反射 payload やエラー文を壊して偽陰性を生む。秘匿の伏字は
        # 永続/配信の境界（record_finding=_redact_json_evidence_pair）に一元化する。
        request_timestamp = time.time()
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                response = await client.request(method, url, content=post_data)
            response_timestamp = time.time()
            pair = {
                "request": {
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "post_data": post_data,
                    "timestamp": request_timestamp,
                },
                "response": {
                    "url": str(response.url),
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                    "timestamp": response_timestamp,
                },
            }
            return response.text, pair
        except Exception:
            return "", {}

    async def run_equivalence_probe(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
        *,
        context: str = "sql",
    ) -> "Optional[tuple]":
        """文字列結合の等価性プローブを 1 フィールドに対して実行する。

        ``context`` に応じたプローブ群を生成して順に投入し、応答本文から
        ``equivalence_probe.evaluate`` で注入可否を判定する。判定が陽性なら
        ``(ProbeVerdict, last_pair)`` を、そうでなければ ``None`` を返す。

        SQLi / XSS の両スキャナから再利用する共通ロジック。投入は各スキャナの
        ``_apply_payload`` に委譲するため、フォーム/URLパラメータ双方に対応する。
        """
        from wscan import equivalence_probe as eqp

        builders = {
            "sql": eqp.sql_probe_set,
            "html_attr": eqp.html_attr_probe_set,
            "js_string": eqp.js_string_probe_set,
        }
        builder = builders.get(context)
        if builder is None:
            return None

        probe_set = builder()
        responses: dict[str, str] = {}
        pairs: dict[str, dict] = {}
        for probe in probe_set.probes:
            # Log probe payloads to the audit trail just like the normal scanner
            # loops, so payloads.jsonl can reproduce a verdict's matched payload.
            await self.log_payload_test(
                field_name, probe.value, f"{self.CHECK_TYPE}_equiv", url
            )
            try:
                source, pair = await self._apply_payload(
                    url, form_index, field_name, probe.value, is_url_param
                )
            except Exception:
                continue
            pairs[probe.name] = pair or {}
            body = (pair.get("response", {}) or {}).get("body") or source or ""
            responses[probe.name] = body

        verdict = eqp.evaluate(probe_set, responses)
        if verdict.injectable:
            # Attach the request/response pair of the probe that actually
            # triggered the verdict, not whichever probe happened to run last
            # (otherwise the recorded evidence points at a different payload).
            matched_pair = pairs.get(verdict.matched_probe, {})
            return verdict, matched_pair
        return None

    async def _evolution_probe(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
    ) -> tuple[str, set[str], dict]:
        """文脈適応 payload 用の特殊文字生存 probe を投入する。

        個別 scanner の検知判定は呼ばず、marker 付き文字列の反射状態だけを
        観測する。失敗時は呼び出し側が従来挙動へ戻れるよう空値を返す。
        """
        try:
            from wscan import context_mutator

            marker = context_mutator.make_marker()
            probe = context_mutator.make_char_probe(marker)
            await self.log_payload_test(
                field_name,
                probe,
                f"{self.CHECK_TYPE}_evolution_probe",
                url,
            )
            if is_url_param:
                source, pair = await self.browser.test_url_param(url, field_name, probe)
            else:
                await self.browser.navigate(url)
                source, pair = await self.browser.fill_and_submit_form(
                    form_index,
                    field_name,
                    probe,
                )
            response_source = (pair.get("response", {}) or {}).get("body") or source or ""
            surviving = context_mutator.surviving_chars(response_source, marker)
            context = context_mutator.detect_context(response_source, marker)
            context["marker"] = marker
            return response_source, surviving, context
        except Exception as exc:
            # probe 失敗（ナビゲーション不能・ブラウザ異常など）も観測可能にする。
            # 文脈適応は失われるが、呼び出し側は空 context で従来挙動へ戻る。
            self._note_wave_degradation("evolution_probe", exc)
            return "", set(), {}

    async def evolved_payloads(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
    ) -> list[str]:
        """追加 wave 用の決定論的 payload 候補を返す。

        ``enable_payload_evolution`` が無効、または probe/mutation が失敗した
        場合は空 list を返し、既存の検知ループを壊さない。
        """
        if not getattr(self.engine, "enable_payload_evolution", True):
            return []
        try:
            from wscan import context_mutator

            _source, surviving, context = await self._evolution_probe(
                url,
                form_index,
                field_name,
                is_url_param,
            )
            marker = context.get("marker") or context_mutator.make_marker()
            payloads = context_mutator.mutate(
                self.CHECK_TYPE,
                context=context,
                surviving=surviving,
                marker=marker,
            )
            cap = getattr(self.engine, "max_payloads", 0)
            if cap and cap > 0:
                payloads = payloads[:cap]
            return payloads
        except Exception as exc:
            self._note_wave_degradation("evolution", exc)
            return []

    async def mutated_payloads(self, field_name: str, url: str, seeds: list[str]) -> list[str]:
        """ペイロード変異（mutation）wave の候補を返す。

        標準掃射・evolution で未検出のとき、シード payload を起点にバイパス変種へ
        「変化」させた候補を投入するためのもの。LLM 非依存
        （:mod:`wscan.payload_mutator`）を常に、LLM 版
        （:meth:`wscan.adaptive_payload.AdaptivePayloadEngine.mutate_payload`）を
        adaptive 有効時に併用する。フラグ無効・失敗時は空 list（従来挙動）。

        max_payloads のキャップは「標準掃射」の絞り込み用なので、mutation wave には
        そのまま適用しない（blind 系がキャップ順で漏れるのを補うのが目的のため）。
        """
        if not getattr(self.engine, "enable_payload_mutation", True):
            return []
        out: list[str] = []
        # ① LLM 非依存の決定論的変異
        try:
            from wscan import payload_mutator
            out.extend(payload_mutator.mutation_payloads(self.CHECK_TYPE, seeds))
        except Exception as exc:
            out = []
            self._note_wave_degradation("mutation", exc)
        # ② LLM 変異（プロバイダ有効時のみ・任意）
        try:
            if getattr(self.engine, "adaptive_enabled", False):
                engine = getattr(self.engine, "adaptive_engine", None)
                if engine is not None:
                    llm_variants = await engine.mutate_payload(
                        self.CHECK_TYPE, list(seeds or []),
                        field_name=field_name, url=url,
                    )
                    out.extend(llm_variants or [])
        except Exception:
            pass
        # 重複除去（順序保持）
        seen: set[str] = set()
        deduped: list[str] = []
        for p in out:
            if p and p not in seen:
                seen.add(p)
                deduped.append(p)
        return deduped

    def current_page_pair(self, url: str) -> dict:
        """
        Return the captured request/response for the page under test.

        Page-level scanners run after navigation, when the browser may already
        have loaded scripts, stylesheets, or images.  Falling back to the latest
        network pair can make header/cookie findings describe an asset instead
        of the document URL.
        """
        network = getattr(self.browser, "network", None)
        if not network:
            return {}
        latest_for_url = getattr(network, "latest_for_url", None)
        if latest_for_url:
            return latest_for_url(url, match_query=False) or {}
        return network.latest() or {}

    async def record_finding(
        self,
        url: str,
        field_name: str,
        payload: str,
        evidence: str,
        pair: dict,
        severity: Optional[str] = None,
        screenshot_b64: Optional[str] = None,
        dialog_confirmed: bool = False,
        dialog_message: str = "",
        confidence: Optional[str] = None,
        evidence_type: str = "",
        evidence_details: Optional[dict] = None,
        reproduction_steps: Optional[list[str]] = None,
        injection_point: Optional[InjectionPoint] = None,
    ) -> Finding:
        """Create and record a finding."""
        if screenshot_b64 is None:
            # When an alert dialog fired, the browser already captured a
            # screenshot at that exact instant -- prefer it so the evidence
            # image actually corresponds to the payload that triggered it.
            dlg_shot = getattr(self.browser, "dialog_screenshot_b64", "") or ""
            if dialog_confirmed and dlg_shot:
                screenshot_b64 = dlg_shot
                if self.monitor:
                    await self.monitor.emit_screenshot(
                        dlg_shot,
                        label=f"[FINDING] {self.CHECK_TYPE} on {field_name}",
                    )
            else:
                screenshot_b64 = await self.browser.screenshot_b64(
                    label=f"[FINDING] {self.CHECK_TYPE} on {field_name}"
                )
        # Dedup: skip exact evidence repeats while preserving distinct signals
        # on the same input。JSON body 注入点は leaf 名が同じでも別入力になり得る
        # (例 /profile/id と /billing/id は共に field_name="id")。_augment_dedup_key に
        # 集約し、engine の _record_finding/_init_checkpoint(finding_dedup_key_for 経由)と
        # **完全に同一キー**にする(記録時のみ 6-tuple で resume 復元が 4-tuple、という
        # 食い違いを防ぐ)。form/url_param は base(4-tuple)のままで回帰ゼロ。
        dedup_key = _augment_dedup_key(
            finding_dedup_key(self.CHECK_TYPE, url, field_name, evidence_type),
            injection_point.location if injection_point is not None else "",
            injection_point.method if injection_point is not None else "",
            injection_point.parameter_id if injection_point is not None else "",
        )
        if dedup_key in self.engine._finding_dedup:
            return None  # duplicate
        self.engine._finding_dedup.add(dedup_key)

        # Auto-assign confidence level
        if confidence is None and dialog_confirmed:
            confidence = "confirmed"
        elif confidence is None:
            # "baseline_response" is never populated in the pair dict by any scanner,
            # so the comparison len(resp_body) - len(base_body) was always equal to
            # len(resp_body), making nearly every finding "likely" regardless of
            # whether the response actually changed.  Default to "tentative" so
            # scanners that care about confidence set it explicitly.
            confidence = "tentative"

        # json_body 注入点の証跡は、永続/配信の**この境界**で伏せる（transport は検出用に
        # 生 pair を返す）。テンプレの兄弟秘匿(body・エコー応答)と認証ヘッダ値を to_dict へ
        # 流す前にマスクする。検出は record_finding 呼び出し前に生 pair で済んでいる。
        if injection_point is not None and injection_point.location == "json_body":
            pair = _redact_json_evidence_pair(pair, injection_point.parameter_id)

        finding = Finding(
            check_type=self.CHECK_TYPE,
            severity=severity or self.SEVERITY,
            url=url,
            field_name=field_name,
            payload=payload,
            evidence=evidence,
            request=pair.get("request", {}),
            response=pair.get("response", {}),
            screenshot_b64=screenshot_b64,
            dialog_confirmed=dialog_confirmed,
            dialog_message=dialog_message,
            # verification_state は Finding.__post_init__ が dialog_confirmed から既定を付与する
            # （新規 finding は必ず非空。_phase_verify を通る verifiable finding は後で上書き）。
            confidence=confidence,
            evidence_type=evidence_type or self.CHECK_TYPE,
            evidence_details=evidence_details or {},
            reproduction_steps=reproduction_steps or self._default_reproduction_steps(
                url, field_name, payload
            ),
            injection_location=(injection_point.location if injection_point else ""),
            injection_pointer=(
                injection_point.parameter_id
                if injection_point and injection_point.location == "json_body"
                else ""
            ),
            injection_method=(
                injection_point.method
                if injection_point and injection_point.location == "json_body"
                else ""
            ),
            injection_template_id=(
                injection_point.template_id if injection_point else ""
            ),
            injection_form_index=(
                injection_point.form_index
                if injection_point and injection_point.location == "form"
                else 0
            ),
        )
        self.findings.append(finding)
        self.engine.all_findings.append(finding)
        if self.monitor:
            await self.monitor.emit_finding(finding.to_dict())
        return finding

    def _default_reproduction_steps(self, url: str, field_name: str, payload: str) -> list[str]:
        return [
            f"Open {url}",
            f"Submit payload to field or parameter '{field_name}'",
            "Compare the resulting response and browser behavior with the baseline.",
        ]
