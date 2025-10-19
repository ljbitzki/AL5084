"""Captura/coleta .pcap"""
import shutil
import time
from datetime import datetime
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

SCAPY_AVAILABLE = True
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, PcapReader, wrpcap, Ether, sniff
except Exception:
    SCAPY_AVAILABLE = False

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

def capture_pcap(output: str, interface: str, duration: int, snaplen: int = 96) -> None:
    """Capture"""
    now = datetime.now()
    filename = now.strftime("%Y%m%d-%I%M%S") + '.pcap'
    ensure_dir(output)
    out = str(output) + '/' + str(filename)
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
            str(out),
            "-s",
            str(snaplen),
            "-F",
            "pcap"
        ]
        run_cmd(cmd)
        return out
    if tcpdump:
        cmd = [
            tcpdump,
            "-i",
            interface,
            "-G",
            str(duration),
            "-W",
            "1",
            "-s",
            str(snaplen),
            "-w", str(out)
            ]
        run_cmd(cmd)
        return out
    if not SCAPY_AVAILABLE:
        raise RuntimeError("No capturers found (tshark/tcpdump/scapy). Please install at least one.")

    print("[WARN] Capturing via Scapy (fallback). There may be loss at high rate.", file=sys.stderr)
    pkts = sniff(iface=interface, timeout=duration)
    wrpcap(str(out), pkts)