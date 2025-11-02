'''
Consolidação em dataset
'''
import csv
import subprocess
import numpy as np
import pandas as pd
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

def which_or_none(prog: str) -> Optional[str]:
    """Checks if the executable exists"""
    return shutil.which(prog)

def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Executes command with minimal logging and validates return."""
    print(f"[CMD] {' '.join(cmd)}", file=sys.stderr)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        raise RuntimeError(f"Falha ao executar {' '.join(cmd)}: {e}") from e
    if cp.returncode != 0:
        # Does not automatically abort, returns stderr useful for diagnostics.
        raise RuntimeError(
            f"Command failed (rc={cp.returncode}): {' '.join(cmd)}\nSTDERR:\n{cp.stderr[:1000]}"
        )
    return cp

def ensure_dir(p: Path) -> None:
    """Checks if directory exists"""
    p.parent.mkdir(parents=True, exist_ok=True)

def now_epoch() -> float:
    """Now in unix timestamp"""
    return time.time()

def to_epoch(ts: datetime) -> float:
    """Conversion to unix timestamp"""
    return ts.replace(tzinfo=timezone.utc).timestamp()

def _standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalizes key names for merging."""
    ren = {
        "saddr": "ip.src",
        "daddr": "ip.dst",
        "sport": "srcport",
        "dport": "dstport",
        "proto": "proto",
        "stime": "stime",
        "ltime": "ltime",
        "dur": "dur",
        "pkts": "pkts",
        "bytes": "bytes",
        "spkts": "spkts",
        "dpkts": "dpkts",
        "sbytes": "sbytes",
        "dbytes": "dbytes",
        "Flow ID": "flow_id",
        "Source IP": "ip.src",
        "Destination IP": "ip.dst",
        "Source Port": "srcport",
        "Destination Port": "dstport",
        "Protocol": "proto",
        "Timestamp": "stime",
    }
    for k, v in ren.items():
        if k in df.columns and v not in df.columns:
            df = df.rename(columns={k: v})
    # Types
    for c in ["srcport", "dstport", "proto"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    for c in ["stime", "ltime", "dur"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    # flow_id if it does not exist
    if "flow_id" not in df.columns and {"ip.src", "srcport", "ip.dst", "dstport", "proto", "stime"}.issubset(df.columns):
        df["flow_id"] = (
            df["ip.src"]
            + ":"
            + df["srcport"].astype(str)
            + "→"
            + df["ip.dst"]
            + ":"
            + df["dstport"].astype(str)
            + "/"
            + df["proto"].astype(str)
            + "@"
            + df["stime"].round(3).astype(str)
        )
    return df


def _nearest_join(left: pd.DataFrame, right: pd.DataFrame, on_tuple_cols: List[str], ts_left: str, ts_right: str, max_delta: float = 1.0) -> pd.DataFrame:
    """Merge by 5-tuple + nearest timestamp join (<= max_delta s)."""
    # Index to accelerate
    left2 = left.copy()
    right2 = right.copy()
    left2["_key"] = left2[on_tuple_cols].astype(str).agg("|".join, axis=1)
    right2["_key"] = right2[on_tuple_cols].astype(str).agg("|".join, axis=1)
    # For each key, merge asof
    merged_parts = []
    for key, lgrp in left2.groupby("_key"):
        rgrp = right2[right2["_key"] == key]
        if rgrp.empty:
            merged_parts.append(lgrp)
            continue
        l = lgrp.sort_values(ts_left)
        r = rgrp.sort_values(ts_right)
        out = pd.merge_asof(l, r, left_on=ts_left, right_on=ts_right, direction="nearest", tolerance=max_delta, suffixes=("", "_r"))
        merged_parts.append(out)
    merged = pd.concat(merged_parts, ignore_index=True, sort=False)
    merged = merged.drop(columns=[c for c in merged.columns if c.endswith("_r") and c in merged.columns and not c == ts_right], errors="ignore")
    return merged


def build_dataset(csv_paths: List[Path], out_csv: Path, labels: Optional[Path] = None, default_label: Optional[str] = None) -> Path:
    """
    Consolidates multiple feature sources into a single CSV.
    - `labels` (optional): CSV with columns [flow_id, label] OR [ip.src, srcport, ip.dst, dstport, proto, label].
    - `default_label` (optional): Label applied to all rows that do not have an explicit label.
    """
    dfs = []
    for p in csv_paths:
        df = pd.read_csv(p)
        df = _standardize_columns(df)
        #df["__source"] = p.suffix.replace(".", "")
        df["__source"] = p
        dfs.append(df)
    if not dfs:
        raise RuntimeError("No CSV to consolidate.")
    # Incremental merge by flow_id when possible; otherwise, by 5-tuple + time
    base = dfs[0]
    for nxt in dfs[1:]:
        if "flow_id" in base.columns and "flow_id" in nxt.columns:
            base = base.merge(nxt.drop_duplicates("flow_id"), on="flow_id", how="left", suffixes=("", "_x"))
        else:
            tuple_cols = ["ip.src", "srcport", "ip.dst", "dstport", "proto"]
            ts_left = "stime" if "stime" in base.columns else ("Timestamp" if "Timestamp" in base.columns else None)
            ts_right = "stime" if "stime" in nxt.columns else ("Timestamp" if "Timestamp" in nxt.columns else None)
            if ts_left and ts_right and set(tuple_cols).issubset(base.columns) and set(tuple_cols).issubset(nxt.columns):
                base = _nearest_join(base, nxt, tuple_cols, ts_left, ts_right, max_delta=1.5)
            else:
                base = base.merge(nxt, how="left")
    # Inject labels
    if labels and Path(labels).exists():
        lbl = pd.read_csv(labels)
        lbl = _standardize_columns(lbl)
        if "flow_id" in lbl.columns and "flow_id" in base.columns:
            base = base.merge(lbl[["flow_id", "label"]], on="flow_id", how="left")
        else:
            tuple_cols = ["ip.src", "srcport", "ip.dst", "dstport", "proto"]
            if set(tuple_cols + ["label"]).issubset(lbl.columns) and set(tuple_cols).issubset(base.columns):
                base = base.merge(lbl[tuple_cols + ["label"]], on=tuple_cols, how="left")
            else:
                raise RuntimeError("Invalid label format. Expected flow_id,label ou 5-tupla+label.")
    if default_label is not None:
        base["label"] = base["label"].fillna(default_label)
    # Cleanup: Remove auxiliary and duplicate columns
    drop_cols = [c for c in base.columns if c.startswith("__")] + [c for c in base.columns if c.endswith("_x")]
    base = base.drop(columns=drop_cols, errors="ignore")
    # Sort columns: keys, times, features, label
    key_cols = [c for c in ["flow_id", "ip.src", "srcport", "ip.dst", "dstport", "proto"] if c in base.columns]
    time_cols = [c for c in ["stime", "ltime", "dur"] if c in base.columns]
    label_cols = ["label"] if "label" in base.columns else []
    feat_cols = [c for c in base.columns if c not in key_cols + time_cols + label_cols]
    ordered = key_cols + time_cols + feat_cols + label_cols
    base = base.reindex(columns=ordered)
    ensure_dir(out_csv)
    now = datetime.now()
    filename = now.strftime("%Y%m%d-%I%M%S") + '-ds.csv'
    out = str(out_csv) + '/' + str(filename)
    base.to_csv(out, index=False)
    return out