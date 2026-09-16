"""0069 Phase1: vulix が wscan の主要 API を同一オブジェクトで re-export する。"""
import vulix
import wscan.engine
import wscan.payload_gen


def test_vulix_reexports_same_objects():
    # 別クラスに二重実行されず、wscan と同一のクラスオブジェクトであること。
    assert vulix.ScanEngine is wscan.engine.ScanEngine
    assert vulix.PayloadGenerator is wscan.payload_gen.PayloadGenerator
    assert vulix.__version__ == wscan.__version__
