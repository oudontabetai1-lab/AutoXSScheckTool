"""
Payload Continuous Learning (A-3)
Records per-check-type payload success/failure across scans.
Successful payloads are promoted to the front of the list in future runs.
"""
import json
from pathlib import Path
from typing import Optional


_DEFAULT_LEARNING_FILE = Path(__file__).parent.parent / "config" / "payload_learning.json"


class PayloadLearner:
    """
    Tracks which payloads succeed/fail per check type and prioritises
    successful ones in future scans.

    Schema of the JSON file::

        {
          "xss": {
            "<script>alert(1)</script>": {"hits": 3, "tries": 5},
            ...
          },
          "sqli": { ... }
        }
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
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(self, check_type: str, payload: str, success: bool) -> None:
        """Record whether a payload succeeded for a check type."""
        ct = self._data.setdefault(check_type, {})
        entry = ct.setdefault(payload, {"hits": 0, "tries": 0})
        entry["tries"] += 1
        if success:
            entry["hits"] += 1

    # ------------------------------------------------------------------
    # Prioritisation
    # ------------------------------------------------------------------

    def sort_payloads(self, check_type: str, payloads: list[str]) -> list[str]:
        """
        Re-order *payloads* so that historically successful ones come first.
        Unknown payloads retain their original relative order at the end.
        """
        ct = self._data.get(check_type, {})
        if not ct:
            return payloads

        def _score(p: str) -> float:
            e = ct.get(p)
            if not e or e["tries"] == 0:
                return -1.0  # unknown → back of list
            return e["hits"] / e["tries"]

        known = [(p, _score(p)) for p in payloads if _score(p) >= 0]
        unknown = [p for p in payloads if _score(p) < 0]
        known.sort(key=lambda x: -x[1])
        return [p for p, _ in known] + unknown

    # ------------------------------------------------------------------
    # Stats helper
    # ------------------------------------------------------------------

    def stats(self, check_type: str) -> list[dict]:
        """Return sorted list of {payload, hits, tries, rate} for a check type."""
        ct = self._data.get(check_type, {})
        rows = []
        for payload, e in ct.items():
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
