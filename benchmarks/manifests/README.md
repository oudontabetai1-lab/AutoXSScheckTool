# benchmark manifests（0034）

E2E benchmark の ground truth 正本（version 付き YAML）を置くディレクトリ。

- 1 ファイル = 1 `BenchmarkSuite`（`benchmark_model.load_manifest_file` が読む schema）。
- `benchmark_model.discover_benchmark_suites(<このディレクトリ>, registry_keys=...)` が
  `*.yaml`/`*.yml` を全て load し、`checks_covered_by_suites` が「vulnerable ground truth を
  持つ check（covered）」と「safe twin を持つ check」を導く。
- ある check の vulnerable/safe twin case をここに追加したら、`config/benchmark_gaps.yaml`
  からその check の gap を外す（外し忘れは registry 完全性テストが `redundant_gaps` で検出）。
- fixture 起動コードは manifest に埋めず、別の allowlist で管理する（設計 0034）。

まだ manifest は未整備（covered 空）。全 scanner は `config/benchmark_gaps.yaml` で明示 gap
として承認され、registry 完全性ゲート（`tests/benchmarks/test_registry_completeness.py`）は
未承認の未計測 scanner を `uncovered`＝`INCOMPLETE` として検出する。
