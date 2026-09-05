"""manifest から分離した fixture 起動 allowlist（0034-R1）。"""
from __future__ import annotations

from contextlib import contextmanager
from importlib import import_module
import math
import socket
import threading
from threading import Thread
import time
from typing import Iterator

from wscan.benchmark_runner import FixtureLauncher


FIXTURE_APPS: dict[str, str] = {
    "realistic_site": "tests.fixtures.realistic_site:create_app",
}


# factory が返らない/uvicorn が should_exit を無視すると、bound された cleanup join 後も daemon
# fixture スレッドが生存放置される。case worker と同じく run_suite ごとに無制限累積してプロセスを
# 枯渇させうる（Codex #133）。case worker と対称に、spawn 前に atomic に予約し worker 終了時に
# 解放する。ハングした serve は解放されず予約が残る＝これが cap の実体。limit はプロセス横断の
# 単一値（instance ごとに違う値を渡すと bound を回避できるため establish 時に検証）。
_fixture_lock = threading.Lock()
_reserved_fixtures = 0
_fixture_limit: int | None = None


def _establish_fixture_limit(cap: int) -> None:
    """プロセス横断の単一 fixture limit を確立/検証する。異なる値の混在は拒否（Codex #133）。"""
    global _fixture_limit
    with _fixture_lock:
        if _fixture_limit is None:
            _fixture_limit = cap
        elif cap != _fixture_limit:
            raise ValueError(
                f"inconsistent max_abandoned_fixtures: {cap} != process-wide {_fixture_limit}"
            )


def _try_reserve_fixture() -> bool:
    """共有 limit 未満なら予約(+1)して True。到達済みなら False（atomic な check-and-reserve）。"""
    global _reserved_fixtures
    with _fixture_lock:
        if _fixture_limit is None or _reserved_fixtures >= _fixture_limit:
            return False
        _reserved_fixtures += 1
        return True


def _release_fixture() -> None:
    global _reserved_fixtures
    with _fixture_lock:
        _reserved_fixtures = max(0, _reserved_fixtures - 1)


def _reserved_fixture_count() -> int:
    with _fixture_lock:
        return _reserved_fixtures


def _reset_fixture_workers() -> None:
    """テスト用: 予約カウンタと共有 limit を初期化する（放置 daemon スレッドは残る）。"""
    global _reserved_fixtures, _fixture_limit
    with _fixture_lock:
        _reserved_fixtures = 0
        _fixture_limit = None


class UvicornFixtureLauncher(FixtureLauncher):
    def __init__(
        self, startup_timeout: float = 5.0, max_abandoned_fixtures: int = 4
    ) -> None:
        # NaN/inf だと deadline 比較が永久 False になり timeout が効かない（Codex #133）。
        if not math.isfinite(startup_timeout) or startup_timeout <= 0:
            raise ValueError("startup_timeout must be finite and positive")
        if max_abandoned_fixtures < 1:
            raise ValueError("max_abandoned_fixtures must be >= 1")
        self.startup_timeout = startup_timeout
        self.max_abandoned_fixtures = max_abandoned_fixtures

    @contextmanager
    def launch(self, fixture_id: str) -> Iterator[str]:
        if fixture_id not in FIXTURE_APPS:
            raise ValueError(f"unknown fixture_id: {fixture_id}")
        # プロセス横断の単一 limit を確立/検証（instance ごとに違う値だと bound を回避できる）。
        _establish_fixture_limit(self.max_abandoned_fixtures)
        # serve を start する前に atomic に予約。取れなければ active+放置が上限＝起動拒否
        # （run_suite が fixture_unavailable にする）。予約は serve 終了時に解放、ハングは保持。
        if not _try_reserve_fixture():
            raise RuntimeError(
                "too many fixture workers; a previous fixture did not stop"
            )

        import uvicorn

        spec = FIXTURE_APPS[fixture_id]
        thread_started = False
        try:
            # bind した socket をそのまま渡し、空きポートの取り直し競合を避ける。
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
                # factory の import/create_app() と server 構築を **daemon スレッド内**で実行し、
                # startup_timeout の bound に含める。同期実行だと factory がハングしたとき deadline
                # が張られる前に無限待ちし、fixture_unavailable を報告できない（Codex #133）。
                holder: dict[str, object] = {}

                def serve() -> None:
                    try:
                        module, factory = spec.split(":", 1)
                        app = getattr(import_module(module), factory)()
                        server = uvicorn.Server(uvicorn.Config(
                            app, host="127.0.0.1", port=port, log_level="error",
                            loop="asyncio", lifespan="off", timeout_graceful_shutdown=1,
                        ))
                        holder["server"] = server
                        server.run(sockets=[sock])
                    except BaseException as exc:
                        holder["error"] = exc
                    finally:
                        # serve が終われば予約解放。ハング（終わらない）なら解放されず予約が残る
                        # ＝これが cap の実体（放置 worker を bound する）。
                        _release_fixture()

                # daemon 化: 起動が stuck（factory ハング or should_exit で止まらない）場合でも、
                # この worker がインタプリタ終了をブロックしないようにする（Codex #133）。
                thread = Thread(
                    target=serve, name=f"benchmark-fixture-{fixture_id}", daemon=True
                )
                thread.start()
                thread_started = True  # 以降 予約解放は serve thread が担う
                try:
                    deadline = time.monotonic() + self.startup_timeout
                    while True:
                        server = holder.get("server")
                        if server is not None and server.started:
                            break
                        if not thread.is_alive():
                            raise RuntimeError("fixture server stopped during startup") from (
                                holder.get("error")  # type: ignore[arg-type]
                            )
                        if time.monotonic() >= deadline:
                            # factory ハングを含む起動全般の timeout。呼び出し側で fixture_unavailable。
                            raise TimeoutError("fixture startup timed out")
                        time.sleep(0.01)
                    yield f"http://127.0.0.1:{port}"
                finally:
                    # cleanup の join は **bound** する。無制限 join すると起動 stuck 時に startup
                    # timeout 例外が run_suite へ届かず fixture_unavailable を報告できない（#133）。
                    # 上限内に止まらなければ daemon を放置して抜ける（予約は serve の finally が
                    # いつか解放、ハング中は保持され続けて cap を効かせる）。
                    server = holder.get("server")
                    if server is not None:
                        server.should_exit = True
                    thread.join(self.startup_timeout)
        finally:
            if not thread_started:
                # serve を start する前に失敗した場合のみ、予約をここで解放（二重解放を防ぐ）。
                _release_fixture()
