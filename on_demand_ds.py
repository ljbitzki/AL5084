#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import List

from ds import build_dataset_unsupervised

def main() -> None:
    """
    Feature directory (can be adjusted if desired for later parameterization)
    """    
    features_dir = Path("features")

    if not features_dir.is_dir():
        print(f"[ds_all] Directory not found: {features_dir.resolve()}")
        return

    # Todos os CSVs dentro de features/
    csv_paths: List[Path] = sorted(features_dir.glob("*.csv"))

    if not csv_paths:
        print(f"[ds_all] No .csv files found in {features_dir.resolve()}")
        return

    print(f"[ds_all] Found {len(csv_paths)} feature files:")
    for p in csv_paths:
        print(f"  - {p}")

    # Calls the existing function, maintaining the current output format.
    out_path = build_dataset_unsupervised(
        csv_paths=csv_paths,
        outdir="datasets",
        save=True,
    )

    print(f"[ds_all] Consolidated dataset saved in: {out_path}")


if __name__ == "__main__":
    main()
