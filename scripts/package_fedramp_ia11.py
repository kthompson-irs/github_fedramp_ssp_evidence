#!/usr/bin/env python3
import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / "fedramp_package_bundle.zip"

if out.exists():
    out.unlink()

shutil.make_archive(str(out.with_suffix("")), "zip", root_dir=root)
print(f"Created {out}")
