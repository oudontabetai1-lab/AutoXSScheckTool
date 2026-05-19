"""TLS and client-certificate configuration helpers."""
from __future__ import annotations

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

    def httpx_options(self) -> dict:
        opts: dict = {"verify": False}
        if self.verify_tls:
            opts["verify"] = self.ca_cert or True
        elif self.ca_cert:
            # A supplied CA bundle means the user expects validation against it.
            opts["verify"] = self.ca_cert
        if self.client_cert and self.client_key:
            opts["cert"] = (self.client_cert, self.client_key)
        elif self.client_cert:
            opts["cert"] = self.client_cert
        return opts
