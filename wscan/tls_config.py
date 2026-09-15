"""TLS and client-certificate configuration helpers."""
from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class TLSConfig:
    """Shared TLS settings for Playwright and httpx transports."""

    client_cert: str = ""
    client_key: str = ""
    client_pfx: str = ""
    client_cert_password: str = ""
    ca_cert: str = ""
    verify_tls: bool = False

    @classmethod
    def from_values(
        cls,
        *,
        client_cert: str = "",
        client_key: str = "",
        client_pfx: str = "",
        client_cert_password: str = "",
        ca_cert: str = "",
        verify_tls: bool = False,
    ) -> "TLSConfig":
        return cls(
            client_cert=str(client_cert or "").strip(),
            client_key=str(client_key or "").strip(),
            client_pfx=str(client_pfx or "").strip(),
            client_cert_password=str(client_cert_password or ""),
            ca_cert=str(ca_cert or "").strip(),
            verify_tls=bool(verify_tls),
        )

    def has_client_certificate(self) -> bool:
        return bool(self.client_pfx or self.client_cert)

    def has_custom_ca(self) -> bool:
        return bool(self.ca_cert)

    def _origin_for(self, url: str) -> str:
        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    def validate_paths(self) -> list[str]:
        errors: list[str] = []
        for label, path in (
            ("client certificate", self.client_cert),
            ("client key", self.client_key),
            ("client PFX", self.client_pfx),
            ("CA certificate", self.ca_cert),
        ):
            if path and not Path(path).expanduser().exists():
                errors.append(f"{label} file not found: {path}")
        if self.client_cert and not self.client_key:
            errors.append("client key is required when using a PEM client certificate")
        if self.client_key and not self.client_cert:
            errors.append("client certificate is required when using a PEM client key")
        return errors

    def playwright_context_options(self, target_url: str) -> dict:
        # Playwright cannot take an arbitrary CA bundle per context. Keep the
        # browser compatible with internal/self-signed targets while still
        # sending the configured client certificate. httpx requests use
        # ``verify_tls`` / ``ca_cert`` for server-certificate validation.
        opts = {"ignore_https_errors": True}
        origin = self._origin_for(target_url)
        if origin and self.client_pfx:
            cert = {"origin": origin, "pfxPath": self.client_pfx}
            if self.client_cert_password:
                cert["passphrase"] = self.client_cert_password
            opts["client_certificates"] = [cert]
        elif origin and self.client_cert and self.client_key:
            cert = {
                "origin": origin,
                "certPath": self.client_cert,
                "keyPath": self.client_key,
            }
            if self.client_cert_password:
                cert["passphrase"] = self.client_cert_password
            opts["client_certificates"] = [cert]
        return opts

    def build_ssl_context(self) -> ssl.SSLContext | None:
        """httpx 0.28 用の明示 SSLContext を構築する。

        httpx 0.28 は ``cert=`` / ``verify="<path>"`` のショートカットを廃止し、
        クライアント証明書付き（mTLS）接続には ``ssl.SSLContext`` を要求する。旧実装は
        ``cert=(crt,key)`` を渡していたため mTLS がサイレントに確立できなかった（F05）。
        検証も client 証明書も不要なら ``None`` を返す（呼び出し側は verify=False）。
        """
        want_validation = self.verify_tls or bool(self.ca_cert)
        has_client = bool(self.client_cert)  # PEM のみ（PFX は httpx 経路では従来非対応）
        if not want_validation and not has_client:
            return None
        if want_validation:
            # CA 指定時はそれで検証、未指定＋verify_tls時はシステム CA。
            context = ssl.create_default_context(cafile=self.ca_cert or None)
        else:
            # 検証は無効（自己署名の内部ターゲット等）だが client 証明書は送る。
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if has_client:
            context.load_cert_chain(
                certfile=self.client_cert,
                keyfile=self.client_key or None,
                password=(self.client_cert_password or None),
            )
        return context

    def httpx_options(self) -> dict:
        context = self.build_ssl_context()
        # httpx は verify に SSLContext を受け取る。None は検証無効(=verify=False)。
        return {"verify": context if context is not None else False}
