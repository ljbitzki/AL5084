#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Union, List

import argparse
import numpy as np
import pandas as pd

from ml_algos import run_iforest, run_lof, run_kmeans_outlier

PathLike = Union[str, Path]

def _ensure_file(path: PathLike) -> Path:
    """
    Ensures that the 'path' directory exists.
    If 'path' has a suffix (looks like a file), it creates the parent;
    if it doesn't, it creates the path itself as a directory.

    Args:
        p (Path): Path to try if exists
    """   
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")
    return p

def _run_algo(
    algo: str,
    df: pd.DataFrame,
    contamination: float,
    min_score: float | None = None,
) -> pd.DataFrame:
    """
    Run one of the algorithms from ml_algos.py on df and return df_scores
    (anomaly_score, is_anomaly, rank) with the same index.

    Args:
        algo (str): Algorithm
        df (pd.DataFrame): Pandas DataFrame
        contamination (float): Contamination
        min_score (float | None, optional): Minimum score. Defaults to None.

    Raises:
        ValueError: Unknown algorithm

    Returns:
        pd.DataFrame: Pandas DataFrame
    """

    if algo == "iforest":
        _, scores = run_iforest(df, contamination=contamination, min_score=min_score)
    elif algo == "lof":
        _, scores = run_lof(df, contamination=contamination, min_score=min_score)
    elif algo == "kmeans":
        _, scores = run_kmeans_outlier(df, contamination=contamination, min_score=min_score)
    else:
        raise ValueError(f"Unknown algo: {algo}")
    return scores


def _print_score_stats(scores: pd.Series, quantiles: List[float]) -> None:
    """
    Prints basic statistics and quantiles for an anomaly_score series.

    Args:
        scores (pd.Series): Scores
        quantiles (List[float]): Basic statistics and quantiles for an anomaly_score series
    """

    print("\n=== Basic statistics for anomaly_score ===")
    print(f"count : {scores.shape[0]}")
    print(f"min   : {scores.min():.6f}")
    print(f"max   : {scores.max():.6f}")
    print(f"mean  : {scores.mean():.6f}")
    print(f"std   : {scores.std(ddof=0):.6f}")

    print("\n=== Quantiles ===")
    q_values = scores.quantile(quantiles)
    for q, val in q_values.items():
        print(f"q{int(q*100):3d} : {val:.6f}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
        "Calculates statistics for the anomaly_score distribution " 
        "to a dataset (baseline) using IF/LOF/KMeans."
        )
    )
    parser.add_argument(
        "--csv",
        required=True,
        help="CSV file of the dataset (ex.: baseline_01.unsupervised.csv)",
    )
    parser.add_argument(
        "--algo",
        default="iforest",
        choices=["iforest", "lof", "kmeans"],
        help="Anomaly algorithm to use (default: iforest)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Target fraction of anomalies (used only for ranking; default: 0.05)",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help=(
            "Minimum absolute score to consider an anomaly (only affects anomalies). "
            "To ignore and use only contamination, use 0.0 (default).."
        ),
    )
    parser.add_argument(
        "--quantiles",
        type=float,
        nargs="+",
        default=[0.9, 0.95, 0.99, 0.995, 0.999],
        help="List of quantiles to calculate (default: 0.9 0.95 0.99 0.995 0.999)",
    )

    args = parser.parse_args()

    csv_path = _ensure_file(args.csv)
    print(f"[+] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path, engine="python")

    print(f"[+] Dataset: {df.shape[0]} lines, {df.shape[1]} columns")
    # Here we pass the entire df; ml_algos._check_X will select only the numeric columns.
    scores_df = _run_algo(
        algo=args.algo,
        df=df,
        contamination=args.contamination,
        min_score=args.min_score if args.min_score > 0 else None,
    )

    # scores_df has columns: anomaly_score, is_anomaly, rank
    scores = scores_df["anomaly_score"]

    _print_score_stats(scores, args.quantis)

    # Optional: Show how many anomalies there are based on the current criteria.
    num_anom = scores_df["is_anomaly"].sum()
    print(f"\n=== Anomaly count (is_anomaly=1) ===")
    print(f"{num_anom} de {scores_df.shape[0]} flows "
          f"({num_anom / scores_df.shape[0] * 100:.2f}%)")

if __name__ == "__main__":
    main()
