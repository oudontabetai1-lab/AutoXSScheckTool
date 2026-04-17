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


_DEFAULT_LEARNING_FILE = Path(__file__).parent.parent / "config" / "payload_learning.json"


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
        domain_ct: dict = {}
        if domain:
            domain_ct = self._data["domains"].get(domain, {}).get(check_type, {})

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

    def stats(self, check_type: str, domain: Optional[str] = None) -> list[dict]:
        """
        Return sorted list of {payload, hits, tries, rate} for a check type.

        If *domain* is given, returns merged global + domain stats.
        """
        global_ct = self._data["global"].get(check_type, {})
        domain_ct: dict = {}
        if domain:
            domain_ct = self._data["domains"].get(domain, {}).get(check_type, {})

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
