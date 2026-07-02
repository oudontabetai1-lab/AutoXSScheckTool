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


def apply_env(*, base_url: str | None = None, api_key: str | None = None, model: str | None = None) -> None:
    """CLI/config/ダッシュボード由来の値を環境変数へ集約する（空値は無視・加算的）。

    既に env が設定済みの場合は **明示指定があるときだけ** 上書きする。これにより
    「env で渡す」運用と「CLI/config で渡す」運用を両立できる。
    """
    if base_url and str(base_url).strip():
        os.environ[ENV_BASE_URL] = str(base_url).strip()
    if api_key and str(api_key).strip():
        os.environ[ENV_API_KEY] = str(api_key).strip()
    if model and str(model).strip():
        os.environ[ENV_MODEL] = str(model).strip()


def set_base_url(base_url: str | None) -> None:
    """ベース URL を env へ設定する。空なら ``WSCAN_LLM_BASE_URL`` を明示削除する。

    低レベルヘルパー。プロバイダの意図（公式か外部互換か）を考慮しないので、
    スキャン単位の設定には :func:`configure_endpoint` を使うこと。
    """
    if base_url and str(base_url).strip():
        os.environ[ENV_BASE_URL] = str(base_url).strip()
    else:
        os.environ.pop(ENV_BASE_URL, None)


def configure_endpoint(provider: str | None, base_url: str | None) -> None:
    """スキャン単位でエンドポイント env を **プロバイダの意図に沿って** 設定する。

    2 つの相反する要求を両立させる:
    - 長時間プロセス（ダッシュボード）で前スキャンのカスタム endpoint を持ち越さない。
    - ``openai_compatible`` で ``WSCAN_LLM_BASE_URL`` 環境変数だけに頼る運用
      （明示的な base URL を渡さない API/旧 config 等）を壊さない。

    ルール:
    - 明示的な ``base_url`` があればそれを設定。
    - ``provider == "openai"``（公式を明示選択）かつ ``base_url`` 空 → 古い
      ``WSCAN_LLM_BASE_URL`` を **クリア**（公式エンドポイントへ）。
    - ``provider == "openai_compatible"`` かつ ``base_url`` 空 → env フォールバック
      （``WSCAN_LLM_BASE_URL`` / ``OPENAI_BASE_URL``）を **保持**（触らない）。
    - その他のプロバイダ → 触らない。

    ※ 公式/互換の区別が必要なので、``canonical_provider`` で正規化する **前** の
      元プロバイダ名を渡すこと。
    """
    if base_url and str(base_url).strip():
        os.environ[ENV_BASE_URL] = str(base_url).strip()
        return
    if provider == "openai":
        # 公式 OpenAI を明示選択した場合のみ、前スキャンのカスタム値をクリアする。
        os.environ.pop(ENV_BASE_URL, None)
    # openai_compatible + 空、またはその他プロバイダ → env フォールバックを保持
