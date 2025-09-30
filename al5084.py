import argparse
import shutil
import os
import time
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SCAPY_AVAILABLE = True
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, PcapReader, wrpcap, Ether
except Exception:
    SCAPY_AVAILABLE = False

def which_or_none(prog: str) -> Optional[str]:
    return shutil.which(prog)

def run_cmd(cmd: List[str], timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    print(f"[CMD] {' '.join(cmd)}", file=sys.stderr)
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        raise RuntimeError(f"Falha ao executar {' '.join(cmd)}: {e}") from e
    if cp.returncode != 0:
        raise RuntimeError(
            f"Comando falhou (rc={cp.returncode}): {' '.join(cmd)}\nSTDERR:\n{cp.stderr[:1000]}"
        )
    return cp

def ensure_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)

def now_epoch() -> float:
    return time.time()

def to_epoch(ts: datetime) -> float:
    return ts.replace(tzinfo=timezone.utc).timestamp()

def capture_pcap(output: Path, interface: str, duration: int, snaplen: int = 96) -> None:
    ensure_dir(output)
    tshark = which_or_none("tshark")
    tcpdump = which_or_none("tcpdump")
    if tshark:
        cmd = [
            tshark,
            "-i",
            interface,
            "-a",
            f"duration:{duration}",
            "-w",
            str(output),
            "-s",
            str(snaplen),
        ]
        run_cmd(cmd)
        return
    if tcpdump:
        cmd = [tcpdump, "-i", interface, "-G", str(duration), "-W", "1", "-s", str(snaplen), "-w", str(output)]
        run_cmd(cmd)
        return
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Nenhum capturador encontrado (tshark/tcpdump/scapy). Instale pelo menos um.")

    from scapy.all import sniff
    print("[WARN] Capturando via Scapy (fallback). Pode haver perda sob alta taxa.", file=sys.stderr)
    pkts = sniff(iface=interface, timeout=duration)
    wrpcap(str(output), pkts)

def main():
    ap = argparse.ArgumentParser(
        prog="al5084",
        description="Pipeline de captura, extração de features, geração de dataset e ML para tráfego de rede.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_cap = sub.add_parser("capture", help="Capturar PCAP de uma interface")
    ap_cap.add_argument("-i", "--iface", required=True, help="Interface (ex: enp0s3, eth0, etc)")
    ap_cap.add_argument("-d", "--duration", type=int, default=60, help="Duração (s)")
    ap_cap.add_argument("-o", "--out", required=True, type=Path, help="Arquivo .pcap de saída")
    ap_cap.add_argument("--snaplen", type=int, default=96, help="Snaplen (bytes)")
    args = ap.parse_args()

    if args.cmd == "capture":
        capture_pcap(args.out, args.iface, args.duration, snaplen=args.snaplen)

if __name__ == "__main__":
    main()