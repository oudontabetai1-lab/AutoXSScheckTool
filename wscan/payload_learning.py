"""
Payload Continuous Learning (A-3)
Records per-check-type payload success/failure across scans.
Successful payloads are promoted to the front of the list in future runs.

Enhanced (⑩): Domain-aware storage keeps per-domain histories separate from
the global pool.  Domain-specific hits are merged and prioritised over the
global average when scanning the same target again.

New JSON schema::

    {
      "global": {
        "xss": {
          "<script>alert(1)</script>": {"hits": 3, "tries": 5}
        }
      },
      "domains": {
        "example.com": {
          "xss": {
            "<img src=x onerror=alert(1)>": {"hits": 5, "tries": 6}
          }
        }
      }
    }

Back-compat: legacy files written with the old flat schema
``{"xss": {...}, "sqli": {...}}`` are automatically migrated to
``{"global": {...}, "domains": {}}`` on first load.
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Optional

from wscan.attempt_ledger import neutralize_payload_for_prompt


_DEFAULT_LEARNING_FILE = Path(__file__).parent.parent / "config" / "payload_learning.json"


def format_learning_for_prompt(
    rows: list[dict],
    *,
    max_success: int = 5,
    min_tries: int = 2,
    max_payload_len: int = 120,
) -> str:
    """学習済みで「効いた」payload を LLM プロンプト用の観測ブロックへ整形する純粋関数。

    `rows` は `PayloadLearner.stats()` が返す {payload, hits, tries, rate} の列。
    **本番は finding を出した payload のみ success=True で記録する**（engine `_record_finding`）ため、
    保存済み行の rate は実質 100%（tries==hits）である。したがって本関数は「過去に効いた（＝
    finding を生んだ）払い」の要約に徹し、`min_tries` 未満（＝1回きり）の行はノイズとして除外する。
    失敗を記録するようになれば rate<1 の行も現れ、下の rate>=0.5 フィルタが意味を持つ（前方互換）。

    有意なデータが無ければ空文字を返す（呼び出し側は「壊れたら安全側」を維持）。

    注意: 呼び出し側は当該 origin 限定の非二重計上バケツ
    （`stats(domain=<origin>, include_global=False)`）を渡すこと。`record` が global と domain の
    両バケツへ書くため、`include_global=True` の既定（global+domain 加算）で domain 付きを渡すと
    1 回の観測が二重計上され `min_tries` を素通りする。global 集計（`domain=None`）は他 origin の
    payload まで混ぜてしまう（クロスオリジン漏洩）。両方を避けるのが origin 限定・非二重計上。
    """
    if not rows:
        return ""

    effective_candidates = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        payload = row.get("payload")
        tries = row.get("tries", 0)
        hits = row.get("hits", 0)
        if not isinstance(payload, str) or not payload:
            continue
        try:
            if tries < min_tries or tries <= 0:
                continue
            rate = row.get("rate")
            if rate is None:
                rate = hits / tries
            if rate >= 0.5:
                effective_candidates.append((payload, hits, tries, rate))
        except (TypeError, ZeroDivisionError):
            continue

    # rate 降順（同率は tries 降順＝観測が多い方が信頼できる）
    effective_candidates.sort(key=lambda item: (-item[3], -item[2]))
    effective = effective_candidates[:max(0, max_success)]

    if not effective:
        return ""

    lines = [
        "LEARNED payloads that produced findings on prior scans",
        "(bias generation toward these proven-effective inputs and craft targeted variations):",
    ]
    lines.extend(
        f"- `{neutralize_payload_for_prompt(payload, max_payload_len)}` -> {hits}/{tries} succeeded"
        for payload, hits, tries, _rate in effective
    )
    return "\n".join(lines)


class PayloadLearner:
    """
    Tracks which payloads succeed/fail per check type and prioritises
    successful ones in future scans.

    Optionally accepts a *domain* string (hostname) to maintain a
    per-domain history alongside the global pool.
    """

    def __init__(self, learning_file: Optional[str] = None):
        self._path = Path(learning_file) if learning_file else _DEFAULT_LEARNING_FILE
        self._data: dict = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                return self._migrate(raw)
            except Exception:
                pass
        return {"global": {}, "domains": {}}

    @staticmethod
    def _migrate(raw: dict) -> dict:
        """Migrate flat legacy schema to the new domain-aware schema."""
        if "global" in raw or "domains" in raw:
            # Already in new format; ensure both keys exist
            raw.setdefault("global", {})
            raw.setdefault("domains", {})
            return raw
        # Legacy flat format: {"xss": {...}, "sqli": {...}}
        return {"global": raw, "domains": {}}

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._data, ensure_ascii=False, indent=2)
        # Atomic write: write to a temp file in the same directory then rename,
        # so concurrent saves never leave a partially-written JSON file.
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".payload_learning_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self._path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        check_type: str,
        payload: str,
        success: bool,
        domain: Optional[str] = None,
    ) -> None:
        """
        Record whether a payload succeeded for a check type.

        If *domain* is supplied the result is stored both globally and
        under the domain-specific bucket.
        """
        self._record_in(self._data["global"], check_type, payload, success)
        if domain:
            domain_data = self._data["domains"].setdefault(domain, {})
            self._record_in(domain_data, check_type, payload, success)

    @staticmethod
    def _record_in(store: dict, check_type: str, payload: str, success: bool) -> None:
        ct = store.setdefault(check_type, {})
        entry = ct.setdefault(payload, {"hits": 0, "tries": 0})
        entry["tries"] += 1
        if success:
            entry["hits"] += 1

    # ------------------------------------------------------------------
    # Prioritisation
    # ------------------------------------------------------------------

    def _resolve_domain_ct(self, check_type: str, domain: Optional[str]) -> dict:
        """domain の per-check バケツを返す。origin キー（scheme://netloc）のときは、
        後方互換で**旧 hostname キー**のバケツも取り込む（純粋な読み取り）。

        学習キーは 0006 G4 で hostname→origin へ移行したが、既存の学習ファイルは
        hostname（例 ``example.com``）で記録されている。origin（``https://example.com``）
        で引くと旧データが丸ごと迷子になり、アップグレード直後にサマリ／並べ替えの
        重み付けが両方失われる。そこで origin ルックアップ時は hostname 由来の旧バケツも
        合算する（同一 observation を二重書きしていないので二重計上ではない＝実観測の合算）。

        注意: 同一ホスト別 scheme/port が複数あると、旧 hostname データはそれら全てに現れる。
        だが旧データは origin 区別が無かった時代のもので、かつ soft な最適化ヒントに過ぎず、
        新規記録は origin 単位で正しく分離される（許容できる有界の後方互換挙動）。
        """
        if not domain:
            return {}
        domains = self._data["domains"]
        primary = domains.get(domain, {}).get(check_type, {})
        legacy_key = None
        if "://" in domain:
            from urllib.parse import urlparse
            host = urlparse(domain).hostname
            if host and host != domain and host in domains:
                legacy_key = host
        if not legacy_key:
            return primary
        legacy = domains.get(legacy_key, {}).get(check_type, {})
        if not legacy:
            return primary
        merged: dict[str, dict] = {p: dict(e) for p, e in primary.items()}
        for p, e in legacy.items():
            if p in merged:
                merged[p] = {
                    "hits": merged[p]["hits"] + e["hits"],
                    "tries": merged[p]["tries"] + e["tries"],
                }
            else:
                merged[p] = {"hits": e["hits"], "tries": e["tries"]}
        return merged

    def sort_payloads(
        self,
        check_type: str,
        payloads: list[str],
        domain: Optional[str] = None,
    ) -> list[str]:
        """
        Re-order *payloads* so that historically successful ones come first.

        When *domain* is provided, domain-specific scores are merged with
        global scores and given a 2× weight boost, so payloads that worked
        on this target previously float to the top.

        Unknown payloads retain their original relative order at the end.
        """
        global_ct = self._data["global"].get(check_type, {})
        domain_ct: dict = self._resolve_domain_ct(check_type, domain)

        if not global_ct and not domain_ct:
            return payloads

        def _score(p: str) -> float:
            g = global_ct.get(p)
            d = domain_ct.get(p)
            g_score = (g["hits"] / g["tries"]) if g and g["tries"] else None
            d_score = (d["hits"] / d["tries"]) if d and d["tries"] else None
            if g_score is None and d_score is None:
                return -1.0  # unknown → back of list
            # Domain-specific score is weighted 2× vs global
            scores = []
            if g_score is not None:
                scores.append(g_score)
            if d_score is not None:
                scores.append(d_score * 2.0)
            return sum(scores) / len(scores)

        known = [(p, _score(p)) for p in payloads if _score(p) >= 0]
        unknown = [p for p in payloads if _score(p) < 0]
        known.sort(key=lambda x: -x[1])
        return [p for p, _ in known] + unknown

    # ------------------------------------------------------------------
    # Stats helper
    # ------------------------------------------------------------------

    def stats(
        self,
        check_type: str,
        domain: Optional[str] = None,
        include_global: bool = True,
    ) -> list[dict]:
        """
        Return sorted list of {payload, hits, tries, rate} for a check type.

        If *domain* is given and *include_global* is True (既定), returns merged
        global + domain stats.  ``record`` writes each domain observation into
        **both** the global and domain buckets, so this merge double-counts a
        domain-scoped observation (1 obs → tries 2).

        Set *include_global* to False with a *domain* to get **domain-only**
        stats: accurate per-target counts (no double-count) that never leak
        other targets' payloads.  ここは 1 学習ファイルを複数ターゲットで共有する際に
        重要で、あるターゲット固有のコールバック URL / トークンを含む成功 payload を
        別ターゲットのプロンプト（＝クラウド LLM へ送信）へ混入させないために使う。
        """
        global_ct: dict = {}
        if include_global:
            global_ct = self._data["global"].get(check_type, {})
        domain_ct: dict = self._resolve_domain_ct(check_type, domain)

        merged: dict[str, dict] = {}
        for payload, e in global_ct.items():
            merged[payload] = {"hits": e["hits"], "tries": e["tries"]}
        for payload, e in domain_ct.items():
            if payload in merged:
                merged[payload]["hits"] += e["hits"]
                merged[payload]["tries"] += e["tries"]
            else:
                merged[payload] = {"hits": e["hits"], "tries": e["tries"]}

        rows = []
        for payload, e in merged.items():
            tries = e.get("tries", 0)
            hits = e.get("hits", 0)
            rows.append({
                "payload": payload,
                "hits": hits,
                "tries": tries,
                "rate": hits / tries if tries else 0.0,
            })
        rows.sort(key=lambda r: -r["rate"])
        return rows

    def domain_stats(self) -> dict[str, list[str]]:
        """Return a mapping of domain → list of check_types that have recorded data."""
        return {
            domain: list(checks.keys())
            for domain, checks in self._data["domains"].items()
        }
