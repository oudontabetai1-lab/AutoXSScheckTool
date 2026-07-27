"""
Mass Assignment Scanner（新クラス・API ファースト連携）
======================================================
OWASP API Top 10 の「Mass Assignment / 過剰割り当て」。クライアントが送れない
はずの特権プロパティ（``role`` / ``isAdmin`` / ``verified`` 等）を JSON ボディに
混ぜて送り、サーバがそれを受理して反映するかを検査する。

検査対象は **API スペック（OpenAPI/Postman）取り込みで得た JSON 操作**
（``engine.api_seed_requests`` の :class:`RequestTemplate`）。各操作について
  1. テンプレートのボディでベースライン応答を取り、
  2. 特権フィールド（一意なセンチネル値つき）を足したボディを送り、
  3. センチネル値がベースラインに無く汚染応答に現れたら過剰割り当てと判定。

検知判定は純粋関数（``augment_body`` / ``detect_mass_assignment``）に切り出す。
"""
from __future__ import annotations

import json
import secrets
from typing import Optional, TYPE_CHECKING

import httpx

from .base import BaseScanner, Finding, merge_template_headers

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# 攻撃者が握れてはいけない特権/機微プロパティ名
PRIVILEGED_FIELDS = (
    "role", "roles", "is_admin", "isAdmin", "admin", "is_staff",
    "is_superuser", "superuser", "verified", "is_verified", "email_verified",
    "active", "is_active", "approved", "permissions", "scope", "scopes",
    "group", "groups", "account_type", "plan", "premium", "balance",
    "credit", "account_balance", "price", "discount",
)


def make_sentinels(fields=PRIVILEGED_FIELDS) -> dict[str, str]:
    """各特権フィールドに一意なセンチネル値を割り当てる（純粋）。

    値を一意にすることで、応答に現れた値がどのフィールド由来か特定でき、
    かつ偶然の一致による誤検知を避けられる。
    """
    token = secrets.token_hex(4)
    return {f: f"wscanMA{token}{i}" for i, f in enumerate(fields)}


def injectable_sentinels(
    base_body: Optional[dict], sentinels: dict[str, str]
) -> dict[str, str]:
    """ベースボディに**無い**特権フィールドだけを残す（純粋）。

    テンプレートが既に ``role``/``isAdmin`` 等を文書化している（＝契約上クライアントが
    送れる）場合、その値を sentinel で上書きして 2xx エコーを「過剰割り当て」と誤検知
    してしまう。文書化済みフィールドは対象外にし、未文書のものだけを注入する。
    """
    base = base_body or {}
    return {k: v for k, v in sentinels.items() if k not in base}


def augment_body(base_body: Optional[dict], sentinels: dict[str, str]) -> dict:
    """ベースボディに特権フィールド（センチネル値）を足した dict を返す（純粋）。

    既に base にあるキーは上書きしない（文書化済みフィールドの保護）。注入対象の
    絞り込みは :func:`injectable_sentinels` で行い、本関数は冪等な合成に徹する。
    """
    out = dict(base_body or {})
    for field_name, value in sentinels.items():
        if field_name in out:
            continue
        out[field_name] = value
    return out


def acceptance_ok(status: int) -> bool:
    """更新が「受理された」とみなせる HTTP ステータスか（純粋）。

    API は 400/422 等のバリデーションエラーでも送信 JSON をそのままエコーする
    ことが多く、その場合 sentinel が応答に現れても特権フィールドは *拒否* されて
    いる。受理（2xx）でないレスポンスは過剰割り当ての証拠にしない（誤検知抑止）。
    """
    return 200 <= int(status) < 300


def detect_mass_assignment(
    baseline_body: str,
    polluted_body: str,
    sentinels: dict[str, str],
) -> Optional[tuple[str, str]]:
    """過剰割り当ての証拠を探す（純粋）。

    センチネル値が汚染応答に現れ、ベースライン応答には無いものを 1 件返す
    （``(field_name, value)``）。無ければ None。ベースラインにも在る値は
    単なる入力反射として除外する（誤検知抑止）。
    """
    base = baseline_body or ""
    polluted = polluted_body or ""
    for field_name, value in sentinels.items():
        if value in polluted and value not in base:
            return field_name, value
    return None


class MassAssignmentScanner(BaseScanner):
    """Mass Assignment（過剰割り当て）スキャナ。API スペック由来の JSON 操作を検査。"""

    CHECK_TYPE = "mass_assignment"
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """渡された ``url`` に一致する API テンプレート（JSON 操作）だけを検査する。

        以前は全テンプレートを一括検査して ``_done`` を立てていたが、エンジンは
        テンプレート URL ごとに ``scan_page`` を呼び `(url, check)` 単位で
        チェックポイントを刻む。URL でフィルタしないと、resume 時に未マークの URL を
        処理する際へ全テンプレート（状態変更系 POST/PUT/PATCH 含む）を再送して
        しまう。URL 一致のテンプレートのみを対象にして冪等性と再開整合性を保つ。
        """
        templates = [
            t for t in (getattr(self.engine, "api_seed_requests", []) or [])
            if getattr(t, "url", None) == url
            and (getattr(t, "method", "GET") or "GET").upper() in ("POST", "PUT", "PATCH")
        ]
        if not templates:
            return []

        if self.monitor:
            await self.monitor.emit_status(
                f"Mass assignment check on {len(templates)} API operation(s) for {url}"
            )

        findings: list[Finding] = []
        for tmpl in templates:
            f = await self._test_template(tmpl)
            if f:
                findings.append(f)
        return findings

    def _client_kwargs(self, content_type: str, url: str) -> dict:
        hdrs: dict = {"Content-Type": content_type}
        if hasattr(self.engine, "auth_headers"):
            base = self.auth_headers_for_url(url)
            base.update(hdrs)
            hdrs = base
        kwargs: dict = {"timeout": getattr(self.engine, "timeout", 15),
                        "follow_redirects": True, "headers": hdrs}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif getattr(self.engine, "proxy", ""):
            kwargs["proxy"] = self.engine.proxy
        return kwargs

    async def _test_template(self, tmpl) -> Optional[Finding]:
        sentinels = make_sentinels()
        base_body = tmpl.json_body if isinstance(tmpl.json_body, dict) else {}
        # 文書化済み（base に既出）の特権フィールドは対象外。未文書のものだけ注入し、
        # 検出も注入したフィールドに限定する（契約上のフィールドの 2xx エコーを誤検知
        # しない）。注入できるものが無ければこのテンプレートはスキップ。
        sentinels = injectable_sentinels(base_body, sentinels)
        if not sentinels:
            return None
        polluted = augment_body(base_body, sentinels)
        kwargs = self._client_kwargs(
            getattr(tmpl, "content_type", "application/json"),
            tmpl.url,
        )
        # スペックで宣言された必須ヘッダ（X-API-Version/tenant 等）を載せる。欠落すると
        # 400/401/404 で検査が空振りするため。ただし認証情報ヘッダ（Authorization/
        # API-key）は利用者の --header / 更新トークン（auth_headers 由来）を spec の
        # example/default で上書きしない（merge_template_headers が保護）。
        tmpl_headers = getattr(tmpl, "headers", None)
        if isinstance(tmpl_headers, dict) and tmpl_headers:
            kwargs["headers"] = merge_template_headers(
                kwargs.get("headers", {}), tmpl_headers
            )
        method = (tmpl.method or "POST").upper()

        baseline_payload = json.dumps(base_body)
        polluted_payload = json.dumps(polluted)
        await self.log_payload_test("(JSON body)", polluted_payload, "mass_assignment", tmpl.url)

        try:
            async with httpx.AsyncClient(**kwargs) as client:
                baseline = await client.request(method, tmpl.url, content=baseline_payload)
                tainted = await client.request(method, tmpl.url, content=polluted_payload)
        except Exception:
            return None

        # 実メソッドの応答で認証失効を検知したらエンジンへ通知する。GET プレフライトでは
        # 検知できない「メソッド限定保護」エンドポイント（GET=404/405, POST=401）で、
        # 失効 cookie のまま検査して空 Finding を「済み」記録するのを防ぐ
        # （_run_api_template_checks が再ログイン+再試行/未マークにする）。
        from wscan import session_guard
        if session_guard.looks_logged_out(
            status=baseline.status_code,
            final_url=str(getattr(baseline, "url", tmpl.url)),
            body=baseline.text,
            login_url=getattr(self.engine, "login_url", ""),
            logged_in_marker=getattr(self.engine, "logged_in_marker", ""),
        ):
            try:
                self.engine._api_auth_failed = True
            except Exception:
                pass
            return None

        # 受理（2xx）された場合のみ過剰割り当てとみなす。400/422 等の
        # バリデーションエラーで送信 JSON がエコーされただけのケースを除外する。
        if not acceptance_ok(tainted.status_code):
            return None

        hit = detect_mass_assignment(baseline.text, tainted.text, sentinels)
        if not hit:
            return None
        field_name, value = hit

        return await self.record_finding(
            url=tmpl.url,
            field_name=f"(JSON body: {field_name})",
            payload=polluted_payload,
            evidence=(
                f"Mass assignment: the privileged property '{field_name}' was "
                f"accepted and reflected (value '{value}') when added to the "
                f"{method} body of {tmpl.url}, but was absent from the baseline "
                f"response. Clients can set fields they should not control "
                f"(e.g. role/admin/verified/balance)."
            ),
            pair={
                "request": {"url": tmpl.url, "method": method, "body": polluted_payload},
                "response": {"status": tainted.status_code, "body": tainted.text[:1000]},
            },
            severity="high",
            confidence="likely",
            evidence_type="mass_assignment",
            evidence_details={"field": field_name, "method": method},
        )
