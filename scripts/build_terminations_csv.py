#!/usr/bin/env python3
import csv, json, os, argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path, default="data/terminations.csv")
    args = parser.parse_args()

    rows = []

    if args.source and args.source.exists():
        with args.source.open() as f:
            rows = list(csv.DictReader(f))
    else:
        raw = os.getenv("TERMINATIONS_JSON", "")
        if raw:
            rows = json.loads(raw)

    if not rows:
        raise SystemExit("No termination data")

    args.output.parent.mkdir(exist_ok=True)

    with args.output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows")

if __name__ == "__main__":
    main()
