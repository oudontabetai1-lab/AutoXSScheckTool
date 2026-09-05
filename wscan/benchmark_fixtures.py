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
# fixture スレッドが生存放置される。case worker と同じく、これも run_suite ごとに無制限累積して
# プロセスを枯渇させうる（Codex #133）。放置された fixture worker をプロセス横断で追跡・cap する。
_fixture_lock = threading.Lock()
_abandoned_fixtures: list[Thread] = []


def _live_abandoned_fixture_count() -> int:
    """死んだ worker を掃除し、生存中の放置 fixture worker 数を返す。"""
    with _fixture_lock:
        _abandoned_fixtures[:] = [t for t in _abandoned_fixtures if t.is_alive()]
        return len(_abandoned_fixtures)


def _register_abandoned_fixture(thread: Thread) -> None:
    with _fixture_lock:
        _abandoned_fixtures.append(thread)


def _reset_abandoned_fixtures() -> None:
    """テスト用: 放置 fixture worker トラッカーを空にする。"""
    with _fixture_lock:
        _abandoned_fixtures.clear()


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
        # 放置 fixture worker が上限なら起動を拒否（run_suite が fixture_unavailable にする）。
        if _live_abandoned_fixture_count() >= self.max_abandoned_fixtures:
            raise RuntimeError(
                "too many abandoned fixture workers; a previous fixture did not stop"
            )

        import uvicorn

        spec = FIXTURE_APPS[fixture_id]
        # bind した socket をそのまま渡し、空きポートの取り直し競合を避ける。
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            # factory の import/create_app() と server 構築を **daemon スレッド内**で実行し、
            # startup_timeout の bound に含める。同期実行だと factory がハングしたとき deadline が
            # 張られる前に無限待ちし、fixture_unavailable を報告できない（Codex #133）。
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

            # daemon 化: 起動が stuck（factory ハング or should_exit で止まらない）場合でも、この
            # worker がインタプリタ終了をブロックしないようにする（Codex #133）。
            thread = Thread(
                target=serve, name=f"benchmark-fixture-{fixture_id}", daemon=True
            )
            thread.start()
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
                # timeout 例外が run_suite へ届かず fixture_unavailable を報告できない（Codex #133）。
                # 上限内に止まらなければ daemon スレッドを放置して抜ける（終了はブロックしない）。
                server = holder.get("server")
                if server is not None:
                    server.should_exit = True
                thread.join(self.startup_timeout)
                if thread.is_alive():
                    # bound 内に止まらなかった＝放置 daemon worker。プロセス横断で追跡し累積を
                    # 上限で bound する（次回以降の launch が上限超過なら拒否）。
                    _register_abandoned_fixture(thread)
