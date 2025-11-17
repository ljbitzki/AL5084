"""Features extraction for dataset"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np

ARGUS_FIELDS = [
    "stime", "ltime", "dur", "saddr", "sport",
    "dir", "daddr", "dport", "proto", "state",
    "pkts", "bytes", "spkts", "dpkts", "sbytes",
    "dbytes", "tos", "stos", "dtos", "apply",
    "swin", "dwin", "sco", "dco", "trans", "rate",
]

TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport",
    "tcp.dstport", "udp.srcport", "udp.dstport", "ip.proto",
    "frame.len", "tcp.flags", "tcp.window_size_value",
]

def which_or_none(prog: str) -> Optional[str]:
    """Checks if the executable exists"""
    return shutil.which(prog)

def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Executes command with minimal logging and validates return."""
    print(f"[CMD] {' '.join(cmd)}", file=sys.stderr)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        raise RuntimeError(f"Failed to execute {' '.join(cmd)}: {e}") from e
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

# Generates CSV of flows via argus/ra (if available).
def extract_with_argus(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Feature extraction with Argus"""
    argus = which_or_none("argus")
    ra = which_or_none("ra")
    if not (argus and ra):
        return None
    ensure_dir(out_csv)
    with tempfile.TemporaryDirectory() as td:
        argus_bin = [argus, "-r", str(pcap), "-w", os.path.join(td, "argus.out")]
        run_cmd(argus_bin)
        # -c , CSV separator; -s selects fields
        sel = ",".join(ARGUS_FIELDS)
        ra_cmd = [
            ra,
            "-r",
            os.path.join(td, "argus.out"),
            "-c",
            ",",
            "-s",
            sel,
        ]
        cp = run_cmd(ra_cmd)
        # Argus does not print header by default
        header = ",".join(ARGUS_FIELDS) + "\n"
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            f.write(header)
            f.write(cp.stdout)
    return out_csv

# Generate CSV of flows via cicflowmeter (Python port)
def extract_with_cicflowmeter(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Feature extraction with CICFlowMeter"""
    cfm = which_or_none("cicflowmeter_XXX")
    if not cfm:
        return None
    ensure_dir(out_csv)
    # Typical CLI: cicflowmeter -f input.pcap -c output.csv
    run_cmd([cfm, "-f", str(pcap), "-c", str(out_csv)])
    return out_csv

# Extract per-packet flows in Python with tshark.
def extract_with_tshark(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Feature extraction with TShark"""
    tshark = which_or_none("tshark")
    if not tshark:
        return None

    ensure_dir(out_csv)

    cmd = [
        tshark,
        "-r", str(pcap),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",  # use TAB
        "-E", "quote=d",       # double-quotes
        "-E", "occurrence=f",  # first occurrence
    ]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]

    cp = run_cmd(cmd)

    # CSV per-packet
    pkt_csv = out_csv.with_suffix(".packets.csv")
    with open(pkt_csv, "w", encoding="utf-8") as f:
        f.write(cp.stdout)

    # Aggregate in flows (directional)
    df = pd.read_csv(
        pkt_csv,
        sep="\t",
        engine="python",
        on_bad_lines="warn",  # or "skip"/"error" according to your tolerance
    )

    # Normalize missing columns (qif not TCP/UDP)
    for c in [
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "tcp.window_size_value",
        "tcp.flags",
    ]:
        if c not in df.columns:
            df[c] = np.nan

    df["srcport"] = df["tcp.srcport"].fillna(df["udp.srcport"]).fillna(0).astype(int)
    df["dstport"] = df["tcp.dstport"].fillna(df["udp.dstport"]).fillna(0).astype(int)
    df["proto"] = pd.to_numeric(df.get("ip.proto", 0), errors="coerce").fillna(0).astype(int)
    df["time"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df["len"] = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0).astype(int)
    df["tcp_window"] = pd.to_numeric(df["tcp.window_size_value"], errors="coerce")
    df["tcp_flags"] = df["tcp.flags"].fillna("").astype(str)

    key_cols = ["ip.src", "ip.dst", "srcport", "dstport", "proto"]
    df = df.dropna(subset=["ip.src", "ip.dst", "time"])

    def aggregate(group: pd.DataFrame) -> pd.Series:
        times = group["time"].to_numpy()
        iats = np.diff(np.sort(times)) if len(times) > 1 else np.array([0.0])
        flags = "".join(group["tcp_flags"].astype(str).tolist())
        return pd.Series(
            {
                "stime": times.min(),
                "ltime": times.max(),
                "dur": times.max() - times.min(),
                "pkts": len(group),
                "bytes": int(group["len"].sum()),
                "pkt_len_mean": float(group["len"].mean()),
                "pkt_len_std": float(group["len"].std(ddof=0) if len(group) > 1 else 0.0),
                "iat_mean": float(iats.mean()),
                "iat_std": float(iats.std(ddof=0) if len(iats) > 1 else 0.0),
                "tcp_window_mean": float(group["tcp_window"].mean(skipna=True)) if group["tcp_window"].notna().any() else 0.0,
                "syn_cnt": flags.count("0x00000002"),
                "fin_cnt": flags.count("0x00000001"),
                "rst_cnt": flags.count("0x00000004"),
                "ack_cnt": flags.count("0x00000010"),
                "psh_cnt": flags.count("0x00000008"),
            }
        )

    flows = df.groupby(key_cols, dropna=False).apply(aggregate).reset_index()

    flows["flow_id"] = (
        flows["ip.src"]
        + ":"
        + flows["srcport"].astype(str)
        + "→"
        + flows["ip.dst"]
        + ":"
        + flows["dstport"].astype(str)
        + "/"
        + flows["proto"].astype(str)
        + "@"
        + flows["stime"].round(3).astype(str)
    )

    flows.to_csv(out_csv, index=False)
    return out_csv

def flow_id(self) -> str:
    """Return flow id"""
    return f"{self.src}:{self.sport}→{self.dst}:{self.dport}/{self.proto}@{self.stime:.3f}"

SCAPY_AVAILABLE = True
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, PcapReader, wrpcap, Ether
except Exception:
    SCAPY_AVAILABLE = False

def extract_with_scapy(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Python Fallback: 5-Tuple Aggregation with Essential Features."""
    if not SCAPY_AVAILABLE:
        return None
    features: Dict[Tuple[str, int, str, int, int], List[Tuple[float, int, int, Optional[int], Optional[int]]]] = {}
    def key_from_pkt(pkt) -> Optional[Tuple[str, int, str, int, int]]:
        ip, proto, sport, dport = None, None, 0, 0
        if IP in pkt:
            ip = pkt[IP]
            proto = ip.proto
            src, dst = ip.src, ip.dst
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            proto = ip6.nh
            src, dst = ip6.src, ip6.dst
        else:
            return None
        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            proto = 6
        elif UDP in pkt:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            proto = 17
        elif ICMP in pkt:
            proto = 1
        else:
            proto = int(proto or 0)
        return (str(src), int(sport), str(dst), int(dport), int(proto))

    with PcapReader(str(pcap)) as rd:
        for pkt in rd:
            ts = float(pkt.time)
            plen = int(len(pkt))
            paylen = int(len(pkt[Raw].load)) if Raw in pkt else 0
            tw = int(pkt[TCP].window) if TCP in pkt else None
            tf = int(pkt[TCP].flags) if TCP in pkt else None
            k = key_from_pkt(pkt)
            if not k:
                continue
            features.setdefault(k, []).append((ts, plen, paylen, tw, tf))

    rows: List[Dict[str, object]] = []
    for (src, sport, dst, dport, proto), arr in features.items():
        arr.sort(key=lambda t: t[0])
        times = np.array([a[0] for a in arr], dtype=float)
        lens = np.array([a[1] for a in arr], dtype=int)
        pays = np.array([a[2] for a in arr], dtype=int)
        wins = np.array([a[3] for a in arr if a[3] is not None], dtype=float)
        flags = [a[4] for a in arr if a[4] is not None]
        iats = np.diff(times) if len(times) > 1 else np.array([0.0])
        rows.append(
            {
                "ip.src": src,
                "srcport": sport,
                "ip.dst": dst,
                "dstport": dport,
                "proto": proto,
                "stime": float(times.min()),
                "ltime": float(times.max()),
                "dur": float(times.max() - times.min()),
                "pkts": int(len(arr)),
                "bytes": int(lens.sum()),
                "payload_bytes": int(pays.sum()),
                "pkt_len_mean": float(lens.mean()),
                "pkt_len_std": float(lens.std(ddof=0) if len(lens) > 1 else 0.0),
                "iat_mean": float(iats.mean()),
                "iat_std": float(iats.std(ddof=0) if len(iats) > 1 else 0.0),
                "tcp_window_mean": float(wins.mean()) if len(wins) else 0.0,
                "syn_cnt": sum(1 for f in flags if f & 0x02),
                "fin_cnt": sum(1 for f in flags if f & 0x01),
                "rst_cnt": sum(1 for f in flags if f & 0x04),
                "ack_cnt": sum(1 for f in flags if f & 0x10),
                "psh_cnt": sum(1 for f in flags if f & 0x08),
            }
        )
    df = pd.DataFrame(rows)
    if df.empty:
        print("[WARN] No flows after extraction (Scapy).", file=sys.stderr)
        df = pd.DataFrame(
            columns=[
                "ip.src",
                "srcport",
                "ip.dst",
                "dstport",
                "proto",
                "stime",
                "ltime",
                "dur",
                "pkts",
                "bytes",
                "payload_bytes",
                "pkt_len_mean",
                "pkt_len_std",
                "iat_mean",
                "iat_std",
                "tcp_window_mean",
                "syn_cnt",
                "fin_cnt",
                "rst_cnt",
                "ack_cnt",
                "psh_cnt",
            ]
        )
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
    ensure_dir(out_csv)
    df.to_csv(out_csv, index=False)
    return out_csv

# Generate CSV of flows via NTLFlowLyzer
def extract_with_ntlflowlyzer(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Feature extraction with NTLFlowLyzer"""
    ntlfl = which_or_none("ntlflowlyzer")
    if not ntlfl:
        return None
    ensure_dir(out_csv)
    # Typical CLI: ntlflowlyzer -c ./NTLFlowLyzer/config.json
    base_file = Path("./base.json")
    config_file = Path("./NTLFlowLyzer/tlflconfig.json")
    try:
        with open(base_file, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        config_data["pcap_file_address"] = "./" + str(pcap)
        config_data["output_file_address"] = "./" + str(out_csv)

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)
          
    finally:
        run_cmd([ntlfl, "-c", str(config_file)])
        return out_csv
        if config_file.exists():
            config_file.unlink()

def extract_features(pcap: Path, out_dir: Path) -> List[Path]:
    """
    Attempts to extract as many features as possible by combining tools.
    Returns a list of generated CSVs (each with a subset of columns).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    generated: List[Path] = []

    #1) Argus (standard tool flows)
    argus_csv = out_dir / (pcap.stem + ".argus.csv")
    if extract_with_argus(pcap, argus_csv):
        generated.append(argus_csv)

    #2) CICFlowMeter (83+ IDS-oriented features)
    cic_csv = out_dir / (pcap.stem + ".cic.csv")
    if extract_with_cicflowmeter(pcap, cic_csv):
        generated.append(cic_csv)

    #3) TShark per-packet → aggregation (basic features + flags)
    tshark_csv = out_dir / (pcap.stem + ".tsharkflows.csv")
    if extract_with_tshark(pcap, tshark_csv):
        generated.append(tshark_csv)

    #4) NTLFlowLyzer (standard tool flows)
    ntlfl_csv = out_dir / (pcap.stem + ".ntlflowlyzer.csv")
    if extract_with_ntlflowlyzer(pcap, ntlfl_csv):
        generated.append(ntlfl_csv)

    #5) Fallback Scapy (always tries last to secure something)
    scapy_csv = out_dir / (pcap.stem + ".scapyflows.csv")
    if extract_with_scapy(pcap, scapy_csv):
        generated.append(scapy_csv)

    #6) Something went wrong and nothing was generated
    if not generated:
        raise RuntimeError("Failure: No tool was able to generate features.")
    return generated
