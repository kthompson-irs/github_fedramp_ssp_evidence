#!/usr/bin/env python3
import csv
from pathlib import Path

def main():
    src = Path("data/terminations_source.csv")
    dst = Path("data/terminations.csv")

    if not src.exists():
        raise SystemExit("Missing source CSV")

    rows = list(csv.DictReader(src.open()))

    if not rows:
        raise SystemExit("No termination rows")

    with dst.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows")

if __name__ == "__main__":
    main()
