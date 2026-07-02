"""
OpenAI 互換 LLM エンドポイントの設定解決（純粋関数）
=====================================================
外部の OpenAI 互換 LLM（NTT tsuzumi 2、Azure AI Foundry、vLLM、LiteLLM、
LM Studio など）を使えるようにするための、ベース URL / API キー / モデル名の
解決ヘルパー。全 LLM 呼び出し箇所（payload_gen / remediation / attack_planner /
adaptive_payload / auto_config / engine）はハードコードした
``https://api.openai.com/v1/chat/completions`` の代わりにここを経由する。

設定の流れ:
- ベース URL は各エンジン/PayloadGenerator/AgentEngine が **構築時に**
  :func:`resolve_instance_base` で解決し、各 LLM 呼び出しへ **明示的に渡す**。
  グローバル env は書き換えない（長時間 serve プロセスで operator の env を
  別スキャンが壊す競合を避けるため）。
- API キーは env（``WSCAN_LLM_API_KEY`` / ``OPENAI_API_KEY``）から読む。秘匿情報は
  コード/コミットに埋めず env で渡す既存方針に合致する。

優先順位:
- ベース URL（``resolve_instance_base``）: 明示引数 > [openai_compatible のみ]
  ``WSCAN_LLM_BASE_URL`` > ``OPENAI_BASE_URL`` > 既定(公式)。公式 ``openai`` は
  明示引数が無ければ env を無視して公式既定を使う。
- API キー: ``WSCAN_LLM_API_KEY`` > ``OPENAI_API_KEY``

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


def resolve_instance_base(provider: str | None, explicit: str | None = None) -> str:
    """インスタンス（PayloadGenerator 等）が使う **具体的な** ベース URL を確定する。

    長時間の serve プロセスでは複数スキャン/リクエストが並行し、グローバル env
    (``WSCAN_LLM_BASE_URL``) を後から書き換えると、進行中スキャンの後続 LLM 呼び出しが
    別エンドポイントに化ける。そこで **構築時に具体的な URL をスナップショット** し、
    各呼び出しはこの値を渡す（呼び出し時に env を読み直さない）。

    - 明示 ``explicit`` があればそれ。
    - ``openai_compatible`` かつ ``explicit`` 空 → env (``WSCAN_LLM_BASE_URL`` /
      ``OPENAI_BASE_URL``) を構築時点で解決。
    - それ以外（公式 ``openai`` 等）→ 公式既定。
    """
    if explicit and str(explicit).strip():
        return str(explicit).strip().rstrip("/")
    if provider == OPENAI_COMPATIBLE:
        return resolve_base_url()
    return DEFAULT_OPENAI_BASE


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


# 注意: 以前はスキャン単位で ``WSCAN_LLM_BASE_URL`` を書き換える env ミューテータ
# （apply_env / set_base_url / configure_endpoint）を持っていたが、長時間の serve
# プロセスでは operator が設定した env を別スキャンが消してしまう競合があった。
# 現在はベース URL を各エンジン/PayloadGenerator/AgentEngine へ **明示的に渡し**、
# グローバル env は一切書き換えない（:func:`resolve_instance_base` で構築時に解決）。
