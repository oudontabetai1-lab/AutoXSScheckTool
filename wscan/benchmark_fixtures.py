"""manifest から分離した fixture 起動 allowlist（0034-R1）。"""
from __future__ import annotations

from contextlib import contextmanager
from importlib import import_module
import socket
from threading import Thread
import time
from typing import Iterator

from wscan.benchmark_runner import FixtureLauncher


FIXTURE_APPS: dict[str, str] = {
    "realistic_site": "tests.fixtures.realistic_site:create_app",
}


class UvicornFixtureLauncher(FixtureLauncher):
    def __init__(self, startup_timeout: float = 5.0) -> None:
        self.startup_timeout = startup_timeout

    @contextmanager
    def launch(self, fixture_id: str) -> Iterator[str]:
        if fixture_id not in FIXTURE_APPS:
            raise ValueError(f"unknown fixture_id: {fixture_id}")

        import uvicorn

        module, factory = FIXTURE_APPS[fixture_id].split(":", 1)
        app = getattr(import_module(module), factory)()
        # bind した socket をそのまま渡し、空きポートの取り直し競合を避ける。
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(
                app, host="127.0.0.1", port=port, log_level="error",
                loop="asyncio", lifespan="off", timeout_graceful_shutdown=1,
            ))
            errors: list[BaseException] = []

            def serve() -> None:
                try:
                    server.run(sockets=[sock])
                except BaseException as exc:
                    errors.append(exc)

            # daemon 化: 起動が stuck した（should_exit で止まらない）場合でも、この worker が
            # インタプリタ終了をブロックしないようにする（Codex #133）。
            thread = Thread(
                target=serve, name=f"benchmark-fixture-{fixture_id}", daemon=True
            )
            thread.start()
            try:
                deadline = time.monotonic() + self.startup_timeout
                while not server.started:
                    if not thread.is_alive():
                        raise RuntimeError("fixture server stopped during startup") from (
                            errors[0] if errors else None
                        )
                    if time.monotonic() >= deadline:
                        raise TimeoutError("fixture startup timed out")
                    time.sleep(0.01)
                yield f"http://127.0.0.1:{port}"
            finally:
                # cleanup の join は **bound** する。起動が stuck して should_exit で止まらない
                # ときに無制限 join すると startup timeout 例外が呼び出し側（run_suite）へ届かず
                # fixture_unavailable を報告できなくなる（Codex #133）。上限内に止まらなければ
                # daemon スレッドを放置して抜ける（終了はブロックしない）。
                server.should_exit = True
                thread.join(self.startup_timeout)
