"""..."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np

ARGUS_FIELDS = [
    "stime", "ltime", "dur", "saddr", "sport", "dir", "daddr", "dport", "proto",
    "state", "pkts", "bytes", "spkts", "dpkts", "sbytes", "dbytes", "tos", "stos", "dtos",
    "apply", "swin", "dwin", "sco", "dco", "trans", "rate",
]

TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "frame.len",
    "tcp.flags",
    "tcp.window_size_value",
]

def which_or_none(prog: str) -> Optional[str]:
    """Verifica se o executável existe"""
    return shutil.which(prog)

def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Executa comando com logging mínimo e valida retorno."""
    print(f"[CMD] {' '.join(cmd)}", file=sys.stderr)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        raise RuntimeError(f"Falha ao executar {' '.join(cmd)}: {e}") from e
    if cp.returncode != 0:
        # Não aborta automaticamente; devolve stderr útil para diagnóstico.
        raise RuntimeError(
            f"Comando falhou (rc={cp.returncode}): {' '.join(cmd)}\nSTDERR:\n{cp.stderr[:1000]}"
        )
    return cp

def ensure_dir(p: Path) -> None:
    """Verifica se o diretório existe"""
    p.parent.mkdir(parents=True, exist_ok=True)

def now_epoch() -> float:
    """Agora em unix timestamp"""
    return time.time()

def to_epoch(ts: datetime) -> float:
    """Conversão para em unix timestamp"""
    return ts.replace(tzinfo=timezone.utc).timestamp()

#Gera CSV de flows via argus/ra (se disponíveis).
def extract_with_argus(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Extração de features com o Argus"""
    argus = which_or_none("argus")
    ra = which_or_none("ra")
    if not (argus and ra):
        return None
    ensure_dir(out_csv)
    with tempfile.TemporaryDirectory() as td:
        argus_bin = [argus, "-r", str(pcap), "-w", os.path.join(td, "argus.out")]
        run_cmd(argus_bin)
        # -c , separador CSV; -s seleciona campos
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
        # ra não imprime header por default
        header = ",".join(ARGUS_FIELDS) + "\n"
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            f.write(header)
            f.write(cp.stdout)
    return out_csv


#Gera CSV de flows via cicflowmeter (Python port)
def extract_with_cicflowmeter(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Extração de features com o CICFlowMeter"""
    cfm = which_or_none("cicflowmeter")
    if not cfm:
        return None
    ensure_dir(out_csv)
    # CLI típico: cicflowmeter -f input.pcap -c output.csv
    run_cmd([cfm, "-f", str(pcap), "-c", str(out_csv)])
    return out_csv

#Extrai per-packet em flows no Python com tshark.
def extract_with_tshark(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Extração de features com o TShark"""
    tshark = which_or_none("tshark")
    if not tshark:
        return None
    ensure_dir(out_csv)
    cmd = [
        tshark,
        "-r",
        str(pcap),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
    ]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    cp = run_cmd(cmd)
    # CSV per-packet
    pkt_csv = out_csv.with_suffix(".packets.csv")
    with open(pkt_csv, "w", encoding="utf-8") as f:
        f.write(cp.stdout)
    # Agregar em flows (direcionais)
    df = pd.read_csv(pkt_csv)

    # Normaliza colunas faltantes (quando não TCP/UDP)
    for c in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.window_size_value", "tcp.flags"]:
        if c not in df.columns:
            df[c] = np.nan

    # Usar fillna entre colunas em vez de operações com DataFrame
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
    # Gera flow_id
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
    """Retorna o flow id"""
    return f"{self.src}:{self.sport}→{self.dst}:{self.dport}/{self.proto}@{self.stime:.3f}"

SCAPY_AVAILABLE = True
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, PcapReader, wrpcap, Ether
except Exception:
    SCAPY_AVAILABLE = False

def extract_with_scapy(pcap: Path, out_csv: Path) -> Optional[Path]:
    """Fallback Python: agrega por 5-tupla direcional com features essenciais."""
    if not SCAPY_AVAILABLE:
        return None
    features: Dict[Tuple[str, int, str, int, int], List[Tuple[float, int, int, Optional[int], Optional[int]]]] = {}
    # value: list of (epoch, pkt_len, payload_len, tcp_window, tcp_flags_int)
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
        print("[WARN] Sem fluxos após extração (Scapy).", file=sys.stderr)
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


def extract_features(pcap: Path, out_dir: Path) -> List[Path]:
    """
    Tenta extrair o máximo de features combinando ferramentas.
    Retorna lista de CSVs gerados (cada um com um subconjunto de colunas).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    generated: List[Path] = []
    # 1) Argus (flows ricos)
    argus_csv = out_dir / (pcap.stem + ".argus.csv")
    if extract_with_argus(pcap, argus_csv):
        generated.append(argus_csv)
    # 2) CICFlowMeter (83+ features orientadas a IDS)
    cic_csv = out_dir / (pcap.stem + ".cic.csv")
    if extract_with_cicflowmeter(pcap, cic_csv):
        generated.append(cic_csv)
    # 3) TShark per-packet → agregação (features básicas + flags)
    tshark_csv = out_dir / (pcap.stem + ".tsharkflows.csv")
    if extract_with_tshark(pcap, tshark_csv):
        generated.append(tshark_csv)
    # 4) Fallback Scapy (sempre tenta por último para garantir algo)
    scapy_csv = out_dir / (pcap.stem + ".scapyflows.csv")
    if extract_with_scapy(pcap, scapy_csv):
        generated.append(scapy_csv)
    if not generated:
        raise RuntimeError("Falha: nenhuma ferramenta conseguiu gerar features.")
    return generated
