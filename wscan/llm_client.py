"""生テキストを返す LLM 呼び出しの共通クライアント。"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Literal

import httpx

from . import llm_endpoint


_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504, 529}

CompletionStatus = Literal[
    "ok", "empty", "unavailable", "transient", "permanent", "blocked"
]


def _gemini_block_reason(data: dict) -> str | None:
    """Gemini の安全フィルタ等によるブロック応答（本文なし）を検出する。

    Gemini は安全ブロック時も HTTP 200 を返し、``promptFeedback.blockReason`` や
    ``finishReason: SAFETY`` 等で本文を返さないことがある。同じ prompt を再試行しても
    無駄なので、これを検出して呼び出し側が収束できるようにする。ブロック理由文字列を
    返す（通常応答なら ``None``）。
    """
    if not isinstance(data, dict):
        return None
    feedback = data.get("promptFeedback") or {}
    if feedback.get("blockReason"):
        return str(feedback["blockReason"])
    candidates = data.get("candidates") or []
    if not candidates:
        return "NO_CANDIDATES"
    first = candidates[0] or {}
    finish = first.get("finishReason")
    # STOP / MAX_TOKENS 以外の終了理由で、かつ本文(parts.text)が無いものはブロック扱い。
    if finish and finish not in ("STOP", "MAX_TOKENS"):
        parts = (first.get("content") or {}).get("parts") or []
        has_text = any(isinstance(p, dict) and p.get("text") for p in parts)
        if not has_text:
            return str(finish)
    return None


class _RetryableResponseError(Exception):
    """成功ステータスだが応答形式が一時的に壊れていることを表す。"""


def is_retryable(status_or_exc: Any) -> bool:
    """HTTP ステータスまたは例外が一時的な失敗を示すか判定する。"""
    if isinstance(status_or_exc, int):
        return status_or_exc in _RETRYABLE_STATUS_CODES

    status_code = getattr(status_or_exc, "status_code", None)
    if isinstance(status_code, int):
        return status_code in _RETRYABLE_STATUS_CODES

    if isinstance(status_or_exc, (
        httpx.TimeoutException,
        httpx.ConnectError,
        httpx.ReadError,
        httpx.WriteError,
        httpx.CloseError,
        httpx.RemoteProtocolError,
        _RetryableResponseError,
    )):
        return True

    # Anthropic SDK は httpx の接続・タイムアウト例外を専用例外で包む。
    return status_or_exc.__class__.__name__ in {"APIConnectionError", "APITimeoutError"}


def backoff_seconds(attempt: int, base: float = 0.5, cap: float = 8.0) -> float:
    """0 始まりの再試行番号から指数バックオフ秒数を計算する。"""
    return min(cap, base * (2 ** max(0, attempt)))


def _retry_after_seconds(response: Any, cap: float = 8.0) -> float | None:
    """Retry-After の秒指定を cap 内で返す。日付形式・不正値は無視する。"""
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    value = headers.get("Retry-After")
    if value is None:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(cap, seconds)


def _completion_result(
    text: str | None,
    status: CompletionStatus,
    return_status: bool,
) -> str | None | tuple[str | None, CompletionStatus]:
    """既定の戻り値を保ち、要求時だけ失敗種別を付与する。"""
    if return_status:
        # empty は呼び出し側が空文字の表現差を意識せず判定できるよう None に正規化する。
        return (text if status == "ok" else None, status)
    return text


async def complete_text(
    pg,
    prompt,
    *,
    max_tokens=400,
    temperature=0.3,
    timeout=None,
    retries=None,
    return_status=False,
) -> str | None | tuple[str | None, CompletionStatus]:
    """設定済みプロバイダへ問い合わせ、生テキストと任意の失敗種別を返す。"""
    provider = getattr(pg, "provider", "none")
    if provider == "none":
        return _completion_result(None, "unavailable", return_status)

    request_timeout = (
        timeout if timeout is not None else getattr(pg, "llm_timeout_seconds", 30)
    )
    max_retries = retries if retries is not None else getattr(pg, "llm_max_retries", 2)
    try:
        request_timeout = float(request_timeout)
        max_retries = max(0, int(max_retries))
    except (TypeError, ValueError):
        return _completion_result(None, "unavailable", return_status)

    api_key = None
    anthropic_client = None
    try:
        if provider == "claude":
            anthropic_client = pg._get_anthropic_client()
            if not anthropic_client:
                return _completion_result(None, "unavailable", return_status)
        elif provider == "openai":
            api_key = getattr(pg, "openai_api_key", None)
            if not api_key:
                return _completion_result(None, "unavailable", return_status)
        elif provider == "gemini":
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                return _completion_result(None, "unavailable", return_status)
        elif provider != "ollama":
            return _completion_result(None, "unavailable", return_status)
    except Exception:
        return _completion_result(None, "unavailable", return_status)

    for attempt in range(max_retries + 1):
        retry_after = None
        try:
            if provider == "claude":
                response = await asyncio.to_thread(
                    anthropic_client.messages.create,
                    model=pg.claude_model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=request_timeout,
                    messages=[{"role": "user", "content": prompt}],
                )
                try:
                    text = response.content[0].text if response.content else None
                    if text is not None and not isinstance(text, str):
                        raise TypeError("LLM response text is not a string")
                except (TypeError, AttributeError, IndexError) as exc:
                    raise _RetryableResponseError(str(exc)) from exc
                if text is None or not text.strip():
                    return _completion_result(text, "empty", return_status)
                return _completion_result(text, "ok", return_status)

            async with httpx.AsyncClient(timeout=request_timeout) as client:
                if provider == "openai":
                    response = await client.post(
                        llm_endpoint.chat_completions_url(pg.openai_base_url),
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={
                            "model": pg.openai_model,
                            "messages": [{"role": "user", "content": prompt}],
                            "max_tokens": max_tokens,
                            "temperature": temperature,
                        },
                    )
                elif provider == "gemini":
                    url = (
                        "https://generativelanguage.googleapis.com/v1beta/models/"
                        f"{pg.gemini_model}:generateContent?key={api_key}"
                    )
                    response = await client.post(
                        url,
                        json={
                            "contents": [{"parts": [{"text": prompt}]}],
                            "generationConfig": {
                                "maxOutputTokens": max_tokens,
                                "temperature": temperature,
                            },
                        },
                    )
                else:
                    response = await client.post(
                        f"{pg.ollama_url}/api/generate",
                        json={
                            "model": pg.ollama_model,
                            "prompt": prompt,
                            "stream": False,
                            "options": {
                                "temperature": temperature,
                                "num_predict": max_tokens,
                            },
                        },
                    )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if provider == "openai":
                        text = data["choices"][0]["message"]["content"]
                    elif provider == "gemini":
                        block = _gemini_block_reason(data)
                        if block is not None:
                            # 安全ブロック等。再試行しても無駄なので blocked(収束)扱い。
                            # LLM 全体は生きているため availability は倒さない。
                            return _completion_result(None, "blocked", return_status)
                        text = data["candidates"][0]["content"]["parts"][0]["text"]
                    else:
                        text = data["response"]
                    if not isinstance(text, str):
                        raise TypeError("LLM response text is not a string")
                    if not text.strip():
                        return _completion_result(text, "empty", return_status)
                    return _completion_result(text, "ok", return_status)
                except (ValueError, TypeError, KeyError, IndexError) as exc:
                    raise _RetryableResponseError(str(exc)) from exc

            failure: Any = response.status_code
            retry_after = _retry_after_seconds(response)
        except Exception as exc:
            failure = exc

        retryable = is_retryable(failure)
        if attempt >= max_retries or not retryable:
            status: CompletionStatus = "transient" if retryable else "permanent"
            return _completion_result(None, status, return_status)
        delay = retry_after if retry_after is not None else backoff_seconds(attempt)
        await asyncio.sleep(delay)

    return _completion_result(None, "transient", return_status)
