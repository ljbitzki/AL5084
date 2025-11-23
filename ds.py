"""Features consolidation in dataset"""
from __future__ import annotations
from pathlib import Path
from datetime import datetime
from typing import Iterable, Union
import pandas as pd

PathLike = Union[str, Path]

# ---------------------------------------------------------------------
# Basic utilities
# ---------------------------------------------------------------------

def _ensure_dir(path: PathLike) -> Path:
    """
    Ensures that the 'path' directory exists.
    If 'path' has a suffix (looks like a file), it creates the parent;
    if it doesn't, it creates the path itself as a directory.
    """
    p = Path(path)
    if p.suffix:
        p.parent.mkdir(parents=True, exist_ok=True)
    else:
        p.mkdir(parents=True, exist_ok=True)
    return p


def _detect_source_tool(df: pd.DataFrame, path: Path) -> str:
    """
    It attempts to identify the extractor from the columns/filename.
    """
    name = path.name.lower()

    # ntflowlyzer has many columns + 'handshake_state', 'label', 'flow_id' etc.
    if "ntflow" in name or "handshake_state" in df.columns or "packets_IAT_mean" in df.columns:
        return "ntflowlyzer"

    # Argus: classic columns saddr/sport/daddr/dport, stime/ltime/dur
    if {"saddr", "sport", "daddr", "dport"}.issubset(df.columns):
        return "argus"

    # Scapyflows: ip.src, ip.dst, srcport, dstport, payload_bytes
    if {"ip.src", "ip.dst", "srcport", "dstport"}.issubset(df.columns) and "payload_bytes" in df.columns:
        return "scapyflows"

    # Tsharkflows: ip.src, ip.dst, srcport, dstport, tcp_window_mean (typically)
    if {"ip.src", "ip.dst", "srcport", "dstport"}.issubset(df.columns) and "tcp_window_mean" in df.columns:
        return "tsharkflows"

    # fallback
    return "unknown"


# ---------------------------------------------------------------------
# Normalization by tool
# ---------------------------------------------------------------------

def _normalize_argus(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes basic Argus columns.
    Example header:
    stime,ltime,dur,saddr,sport,dir,daddr,dport,proto,state,pkts,bytes,...
    and below a line with:
      StartTime,LastTime,Dur,SrcAddr,Sport,...
    """
    df = df.copy()

    # If the first line is a "human-readable" header (StartTime, SrcAddr, etc.), discard it.
    if "stime" in df.columns and len(df) > 0:
        first_val = str(df.iloc[0]["stime"]).strip()
        if first_val.lower() in {"starttime", "stime"}:
            df = df.iloc[1:].reset_index(drop=True)

    rename_map = {
        "saddr": "src_ip",
        "daddr": "dst_ip",
        "sport": "src_port",
        "dport": "dst_port",
        "proto": "proto",
        "stime": "stime",
        "ltime": "ltime",
        "dur": "dur",
        "pkts": "pkts",
        "bytes": "bytes",
        "TotPkts": "pkts",
        "TotBytes": "bytes",
    }
    df = df.rename(columns=rename_map)

    # Converts certain numeric fields.
    for col in ["src_port", "dst_port", "proto", "dur", "pkts", "bytes"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def _normalize_scapyflows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes basic columns in Scapyflows.
    Typical header:
      ip.src,srcport,ip.dst,dstport,proto,stime,ltime,dur,pkts,bytes,...
    """
    df = df.copy()
    df = df.rename(columns={
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
    })
    # ports, proto, dur, pkts, bytes usually come in good shape.
    return df


def _normalize_tsharkflows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes basic tsharkflow columns.
    Typical header:
      ip.src,ip.dst,srcport,dstport,proto,stime,ltime,dur,pkts,bytes,...
    """
    df = df.copy()
    df = df.rename(columns={
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
    })
    return df


def _normalize_ntflowlyzer(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes basic columns of ntflowlyzer.
    Header (partial):
      flow_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,duration,
      packets_count,total_payload_bytes,total_header_bytes,...,label
    """
    df = df.copy()

    rename_map = {
        "protocol": "proto",
        "duration": "dur",
        "packets_count": "pkts",
    }
    df = df.rename(columns=rename_map)

    # If there's a payload and a header, we create a "bytes" column to be at least minimally comparable.
    if "total_payload_bytes" in df.columns and "total_header_bytes" in df.columns:
        df["bytes"] = pd.to_numeric(df["total_payload_bytes"], errors="coerce").fillna(0)
        df["bytes"] += pd.to_numeric(df["total_header_bytes"], errors="coerce").fillna(0)

    # Do not treat 'label' as ground truth here -> rename
    if "label" in df.columns:
        df = df.rename(columns={"label": "ntflow_label"})

    return df


def _normalize_common(df: pd.DataFrame, source: str) -> pd.DataFrame:
    """
    Applies specific normalizations per tool + common adjustments.
    Ensures, when possible, columns:
      src_ip, dst_ip, src_port, dst_port, proto, dur, pkts, bytes, stime, ltime
    """
    if source == "argus":
        df = _normalize_argus(df)
    elif source == "scapyflows":
        df = _normalize_scapyflows(df)
    elif source == "tsharkflows":
        df = _normalize_tsharkflows(df)
    elif source == "ntflowlyzer":
        df = _normalize_ntflowlyzer(df)
    else:
        df = df.copy()

    # Mark the origin.
    df["source_tool"] = source

    return df


# ---------------------------------------------------------------------
# Main functions: unsupervised mode
# ---------------------------------------------------------------------

def load_features(csv_paths: Union[PathLike, Iterable[PathLike]]) -> pd.DataFrame:
    """
    Loads one or more CSV files of features/flows (argus, scapyflows, tsharkflows, ntflowlyzer),
    detects the source, normalizes basic columns, and concatenates everything.
    """
    if isinstance(csv_paths, (str, Path)):
        csv_paths = [csv_paths]

    dfs = []
    for path in csv_paths:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Feature CSV not found: {p}")

        # engine="python" makes reading more tolerant
        df = pd.read_csv(p, engine="python")
        source = _detect_source_tool(df, p)

        df_norm = _normalize_common(df, source)
        df_norm["__source_csv"] = p.name

        dfs.append(df_norm)

    if not dfs:
        raise ValueError("No feature CSVs were provided.")

    features = pd.concat(dfs, ignore_index=True)
    return features


def build_dataset_unsupervised(
    csv_paths: Union[PathLike, Iterable[PathLike]],
    *,
    outdir: PathLike = "datasets",
    save: bool = True,
) -> pd.DataFrame:
    """
    Generates an unsupervised dataset (without label ground truth) from the feature CSVs in 'features/' (argus/scapyflows/tsharkflows/ntflowlyzer).
    - Renames columns to a common minimum convention:
    src_ip, dst_ip, src_port, dst_port, proto, dur, pkts, bytes, ...
    - Maintains the specific columns for each tool (ntflowlyzer, argus, etc.).
    - If a tool 'label' column exists (in the case of ntflowlyzer), renames it to 'ntflow_label' and does NOT treat it as ground truth.
    - Adds columns:
    source_tool -> argus / scapyflows / tsharkflows / ntflowlyzer / unknown
    __source_csv -> source file name
    Returns the resulting DataFrame and, if save=True, saves it to an outdir.
    """
    features = load_features(csv_paths)

    if save:
        _ensure_dir(outdir)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"unsupervised.{timestamp}.csv"
        out_path = Path(outdir) / out_name
        features.to_csv(out_path, index=False)
        print(f"[ds] Unsupervised dataset saved to {out_path}")
    return out_path
