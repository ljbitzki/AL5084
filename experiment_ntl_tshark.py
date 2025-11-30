#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Union, Tuple, List

import argparse
import pandas as pd

from ml_unsupervised import run_iforest, run_lof, run_kmeans_outlier

PathLike = Union[str, Path]

def _ensure_file(path: PathLike) -> Path:
    """
    Checks if directory/file exists

    Args:
        path (PathLike): A path to try

    Raises:
        FileNotFoundError: File not found:

    Returns:
        Path: Path
    """    
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")
    return p

def load_ntflow_csv(path: PathLike) -> pd.DataFrame:
    """
    Process NTLFlowLyzer flows in csv

    Args:
        path (PathLike): Path to NTLFlowLyzer csv file

    Returns:
        pd.DataFrame: all headers
    """    

    p = _ensure_file(path)
    df = pd.read_csv(p, engine="python")

    rename_map = {
        "protocol": "proto",
        "duration": "dur",
        "packets_count": "pkts",
    }
    df = df.rename(columns=rename_map)

    if "label" in df.columns:
        df = df.rename(columns={"label": "ntflow_label"})

    if "total_payload_bytes" in df.columns and "total_header_bytes" in df.columns:
        df["bytes"] = (
            pd.to_numeric(df["total_payload_bytes"], errors="coerce").fillna(0)
            + pd.to_numeric(df["total_header_bytes"], errors="coerce").fillna(0)
        )

    return df


def load_tsharkflows_csv(path: PathLike) -> pd.DataFrame:
    """
    Process tshark flows in csv

    Args:
        path (PathLike): Path to tshark csv file

    Returns:
        pd.DataFrame: Typical Header: ip.src,ip.dst,srcport,dstport,proto,stime,ltime,dur,pkts,bytes,...
    """    
    
    p = _ensure_file(path)
    df = pd.read_csv(p, engine="python")

    df = df.rename(columns={
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
        "srcport": "src_port",
        "dstport": "dst_port",
    })

    for col in ["src_port", "dst_port", "proto", "dur", "pkts", "bytes"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def load_scapyflows_csv(path: PathLike) -> pd.DataFrame:
    """
    Process scapy flows in csv

    Args:
        path (PathLike): Path to scapy csv file

    Returns:
        pd.DataFrame: Typical Header: ip.src,srcport,ip.dst,dstport,proto,stime,ltime,dur,pkts,bytes,payload_bytes,...
    """  

    p = _ensure_file(path)
    df = pd.read_csv(p, engine="python")

    df = df.rename(columns={
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
        "srcport": "src_port",
        "dstport": "dst_port",
    })

    for col in ["src_port", "dst_port", "proto", "dur", "pkts", "bytes"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def load_other_flows_csv(path: PathLike) -> Tuple[pd.DataFrame, str]:
    """
    Detects whether the CSV is from tsharkflows or scapyflows based on the columns,
    loads and normalizes it appropriately.

    Args:
        path (PathLike):Path to a csv file

    Raises:
        ValueError: Could not detect tool

    Returns:
        Tuple[pd.DataFrame, str]: (df, tool_name) with tool_name in {"tsharkflows", "scapyflows"}.
    """    

    p = _ensure_file(path)
    df_raw = pd.read_csv(p, engine="python")

    cols = set(df_raw.columns)

    if {"ip.src", "ip.dst", "srcport", "dstport"}.issubset(cols) and "payload_bytes" in cols:
        df = load_scapyflows_csv(p)
        return df, "scapyflows"

    if {"ip.src", "ip.dst", "srcport", "dstport"}.issubset(cols):
        df = load_tsharkflows_csv(p)
        return df, "tsharkflows"

    raise ValueError(f"Could not detect tool type (tshark/scapy) from columns of {p}")

def _add_flow_key(df: pd.DataFrame) -> pd.DataFrame:
    """flow_key (for intersection)

    Args:
        df (pd.DataFrame): Pandas DataFrame

    Returns:
        pd.DataFrame: Pandas DataFrame with flow_key
    """    

    needed = ["src_ip", "dst_ip", "src_port", "dst_port", "proto"]
    if not all(c in df.columns for c in needed):
        return df

    df = df.copy()
    for col in ["src_ip", "dst_ip"]:
        df[col] = df[col].astype(str)

    for col in ["src_port", "dst_port", "proto"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(-1).astype(int)

    df["flow_key"] = (
        df["src_ip"]
        + ":"
        + df["src_port"].astype(str)
        + "→"
        + df["dst_ip"]
        + ":"
        + df["dst_port"].astype(str)
        + "/"
        + df["proto"].astype(str)
    )
    return df

def _run_algo_on_tool(
    algo: str,
    df: pd.DataFrame,
    contamination: float,
    min_score: float | None = None,
) -> pd.DataFrame:
    """
    Run one of the algorithms on df and return df_scores (anomaly_score, is_anomaly, rank)
    with the same index as df.
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

def run_experiment(
    ntflow_csv: PathLike,
    other_csv: PathLike,
    *,
    contamination: float = 0.05,
    top_n: int = 15,
    algos: List[str] = None,
    min_score: float | None = None,
) -> None:
    """
    Run the experiment

    Args:
        ntflow_csv (PathLike): Path to NTLFlowLyzer csv file
        other_csv (PathLike): Path to another tool csv file
        contamination (float, optional): contamination. Defaults to 0.05.
        top_n (int, optional): How many lines to print. Defaults to 15.
        algos (List[str], optional): algorith picker. Defaults to None.
        min_score (float | None, optional): minimum score to consider. Defaults to None.
    """
    if algos is None:
        algos = ["iforest"]

    #  ntflowlyzer 
    df_nt = load_ntflow_csv(ntflow_csv)
    print(f"\nntflowlyzer: {df_nt.shape[0]} flows, {df_nt.shape[1]} columns")

    meta_cols_nt = [c for c in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "timestamp"] if c in df_nt.columns]
    meta_nt = df_nt[meta_cols_nt].copy() if meta_cols_nt else pd.DataFrame(index=df_nt.index)

    #  other tools 
    df_other, tool_name = load_other_flows_csv(other_csv)
    print(f"{tool_name}: {df_other.shape[0]} flows, {df_other.shape[1]} columns")

    meta_cols_ot = [c for c in ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "stime", "ltime"] if c in df_other.columns]
    meta_ot = df_other[meta_cols_ot].copy() if meta_cols_ot else pd.DataFrame(index=df_other.index)

    #  for each algorithm 
    for algo in algos:
        print("\n" + "=" * 60)
        print(f" ALGORITHM: {algo.upper()}")
        print("=" * 60)

        # ntflow
        print("\n[ntflowlyzer] Running", algo)
        scores_nt = _run_algo_on_tool(algo, df_nt, contamination=contamination, min_score=min_score)
        res_nt = meta_nt.join(scores_nt)
        res_nt = _add_flow_key(res_nt)
        res_nt = res_nt.sort_values("anomaly_score", ascending=False)

        # other tool
        print(f"[{tool_name}] Running", algo)
        scores_ot = _run_algo_on_tool(algo, df_other, contamination=contamination, min_score=min_score)
        res_ot = meta_ot.join(scores_ot)
        res_ot = _add_flow_key(res_ot)
        res_ot = res_ot.sort_values("anomaly_score", ascending=False)

        print(f"[ntflowlyzer/{algo}] anomalies={res_nt['is_anomaly'].sum()} de {len(res_nt)} flows")
        print(f"[{tool_name}/{algo}] anomalies={res_ot['is_anomaly'].sum()} de {len(res_ot)} flows")

        # Top-N
        anom_nt = res_nt[res_nt["is_anomaly"] == 1]
        anom_ot = res_ot[res_ot["is_anomaly"] == 1]

        print("\n------------------------------")
        print(" TOP N ANOMALIES - NTFLOWLYZER")
        print("------------------------------")
        print(anom_nt.head(top_n).to_string(index=False))

        print(f"\n-------------------------------")
        print(f" TOP N ANOMALIES - {tool_name.upper()}")
        print("-------------------------------")
        print(anom_ot.head(top_n).to_string(index=False))


        # Intersection by flow_key
        if "flow_key" in res_nt.columns and "flow_key" in res_ot.columns:
            top_nt = anom_nt.head(top_n).copy()
            top_ot = anom_ot.head(top_n).copy()
            inter = top_nt.merge(
                top_ot,
                on="flow_key",
                how="inner",
                suffixes=("_nt", f"_{tool_name}"),
            )

            print("\n----------------------------------------")
            print(" INTERSECTION BETWEEN TOP N (flow_key)")
            print(f" (ntflowlyzer vs {tool_name}, algo={algo})")
            print("----------------------------------------")

            if inter.empty:
                print("No intersection was found between the TOP N values ​​of the two tools.")
            else:
                cols_to_show = []
                for c in [
                    "flow_key",
                    "src_ip_nt", "dst_ip_nt", "src_port_nt", "dst_port_nt", "proto_nt",
                    "anomaly_score_nt", "rank_nt",
                    f"anomaly_score_{tool_name}", f"rank_{tool_name}",
                ]:
                    if c in inter.columns:
                        cols_to_show.append(c)

                # If there are ranks, sort by average.
                if "rank_nt" in inter.columns and f"rank_{tool_name}" in inter.columns:
                    inter["rank_mean"] = inter[["rank_nt", f"rank_{tool_name}"]].mean(axis=1)
                    inter = inter.sort_values("rank_mean")

                print(inter[cols_to_show].to_string(index=False))
        else:
            print("\n[[WARNING] Intersection could not be calculated: 'flow_key' missing.")


def main() -> None:
    """
    Main function with argparse
    """    
    parser = argparse.ArgumentParser(
        description="Experiment: ntflowlyzer vs tshark/scapy with various anomaly algorithms."
    )
    parser.add_argument("--ntflow", required=True, help="CSV flows from ntflowlyzer")
    parser.add_argument("--other", required=True, help="CSV flows from tsharkflows OR scapyflows")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Expected fraction of anomalies (default: 0.05)")
    parser.add_argument("--min_score", type=float, default=10,
                        help="Minimum anomaly score (default: 0.05)")
    parser.add_argument("--top-n", type=int, default=15,
                        help="Number of most suspicious flows to show/intersect(default: 15)")
    parser.add_argument(
        "--algo",
        default="iforest",
        help="Algorithm: iforest, lof, kmeans ou all (default: iforest)",
    )

    args = parser.parse_args()

    if args.algo == "all":
        algos = ["iforest", "lof", "kmeans"]
    else:
        algos = [args.algo]

    run_experiment(
        ntflow_csv=args.ntflow,
        other_csv=args.other,
        contamination=args.contamination,
        min_score=args.min_score,
        top_n=args.top_n,
        algos=algos,
    )

if __name__ == "__main__":
    main()
