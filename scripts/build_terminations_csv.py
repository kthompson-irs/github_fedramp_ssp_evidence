#!/usr/bin/env python3
import csv, argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    src = Path(args.source)
    dst = Path(args.output)

    if not src.exists():
        raise SystemExit("Missing source CSV")

    rows = list(csv.DictReader(src.open()))

    if not rows:
        raise SystemExit("No termination rows")

    dst.parent.mkdir(exist_ok=True)

    with dst.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows")

if __name__ == "__main__":
    main()
