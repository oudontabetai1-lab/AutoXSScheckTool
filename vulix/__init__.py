"""Vulix — self-learning browser security exploration engine.

0069 Phase 1（加算的リブランド）: 現行実装 ``wscan`` の**薄い re-export**。外部から使う主要
公開 API を ``vulix`` 名で参照できるようにし、import 面を Vulix へ移す土台を作る。実体
（``wscan/`` → ``vulix/`` のディレクトリ移動・全 import 書換え）は OPEN PR 消化後の Phase 2 で行う。

ここでは**同一のクラスオブジェクト**を re-export する（サブモジュールの二重実行を避けるため、
``import vulix.engine`` 形のサブモジュール別名は Phase 2 で正式に用意する。現時点は
``from vulix import ScanEngine`` 等の主要エントリのみ）。
"""
from wscan import __version__
from wscan.engine import ScanEngine
from wscan.payload_gen import PayloadGenerator

__all__ = ["ScanEngine", "PayloadGenerator", "__version__"]
