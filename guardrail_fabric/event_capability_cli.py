"""CLI for annotating event-capability records with Guardrail Fabric policy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .event_capability_policy import annotate_event_capability_records


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid event-capability JSON: {exc}") from exc


def extract_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("records", "results"):
            items = value.get(key)
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        data = value.get("data")
        if isinstance(data, dict):
            return extract_records(data)
    raise SystemExit("input must be a list, records/results envelope, or data.records")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Annotate event-capability records with Guardrail Fabric policy outcomes.")
    parser.add_argument("--input", required=True, help="event-capability record JSON file")
    parser.add_argument("--out", help="optional output path")
    args = parser.parse_args(argv)

    records = annotate_event_capability_records(extract_records(load_json(Path(args.input))))
    text = json.dumps(records, indent=2, sort_keys=True) + "\n"
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
