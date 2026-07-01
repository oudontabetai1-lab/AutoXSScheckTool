"""
OpenAI 互換 LLM エンドポイントの設定解決（純粋関数）
=====================================================
外部の OpenAI 互換 LLM（NTT tsuzumi 2、Azure AI Foundry、vLLM、LiteLLM、
LM Studio など）を使えるようにするための、ベース URL / API キー / モデル名の
解決ヘルパー。全 LLM 呼び出し箇所（payload_gen / remediation / attack_planner /
adaptive_payload / auto_config / engine）はハードコードした
``https://api.openai.com/v1/chat/completions`` の代わりにここを経由する。

設定の流れ（CLI/config/ダッシュボード → env → ここ）:
- CLI/config/ダッシュボードで指定された値は起動時に **環境変数へ集約** される
  （`apply_env` 参照）。本モジュールは env のみを読むため、どの設定経路から来ても
  一貫して解決できる。秘匿情報（API キー）はコード/コミットに埋めず env で渡す
  という既存方針にも合致する。

優先順位:
- ベース URL: 明示引数 > ``WSCAN_LLM_BASE_URL`` > ``OPENAI_BASE_URL`` > 既定(公式)
- API キー  : ``WSCAN_LLM_API_KEY`` > ``OPENAI_API_KEY``

``provider`` は UI/CLI 上は ``openai_compatible`` を選べるが、内部的には
``openai`` と同じコード経路（chat/completions 形式）で処理する。両者を
:func:`canonical_provider` で ``openai`` に正規化する。
"""
from __future__ import annotations

import os

# 公式 OpenAI のベース URL（未設定時の既定）
DEFAULT_OPENAI_BASE = "https://api.openai.com/v1"

# UI/CLI/config 上で使う「外部 OpenAI 互換」プロバイダ名
OPENAI_COMPATIBLE = "openai_compatible"

# 環境変数名（本モジュールが読む集約先）
ENV_BASE_URL = "WSCAN_LLM_BASE_URL"
ENV_API_KEY = "WSCAN_LLM_API_KEY"
ENV_MODEL = "WSCAN_LLM_MODEL"


def canonical_provider(provider: str | None) -> str:
    """``openai_compatible`` を内部処理用に ``openai`` へ正規化する。"""
    if provider == OPENAI_COMPATIBLE:
        return "openai"
    return provider or ""


def resolve_base_url(configured: str | None = None) -> str:
    """OpenAI 互換エンドポイントのベース URL を解決する（末尾スラッシュ除去）。"""
    for value in (configured, os.environ.get(ENV_BASE_URL), os.environ.get("OPENAI_BASE_URL")):
        if value and str(value).strip():
            return str(value).strip().rstrip("/")
    return DEFAULT_OPENAI_BASE


def chat_completions_url(configured_base: str | None = None) -> str:
    """chat/completions のフル URL を返す。

    ベース URL が既に ``/chat/completions`` で終わるならそのまま尊重し、
    ``/v1`` 等で終わるなら ``/chat/completions`` を付加する。
    """
    base = resolve_base_url(configured_base)
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def resolve_api_key() -> str | None:
    """API キーを解決する（``WSCAN_LLM_API_KEY`` 優先、``OPENAI_API_KEY`` 後方互換）。"""
    for name in (ENV_API_KEY, "OPENAI_API_KEY"):
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return None


def api_key_present() -> bool:
    """OpenAI 互換エンドポイント用の API キーが設定済みか。"""
    return resolve_api_key() is not None


def is_custom_endpoint() -> bool:
    """公式 OpenAI 以外（外部互換エンドポイント）を指しているか。"""
    return resolve_base_url() != DEFAULT_OPENAI_BASE


def apply_env(*, base_url: str | None = None, api_key: str | None = None, model: str | None = None) -> None:
    """CLI/config/ダッシュボード由来の値を環境変数へ集約する（空値は無視）。

    既に env が設定済みの場合は **明示指定があるときだけ** 上書きする。これにより
    「env で渡す」運用と「CLI/config で渡す」運用を両立できる。
    """
    if base_url and str(base_url).strip():
        os.environ[ENV_BASE_URL] = str(base_url).strip()
    if api_key and str(api_key).strip():
        os.environ[ENV_API_KEY] = str(api_key).strip()
    if model and str(model).strip():
        os.environ[ENV_MODEL] = str(model).strip()
