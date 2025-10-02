"""..."""
import shutil
import time
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

def capture_pcap(output: Path, interface: str, duration: int, snaplen: int = 96) -> None:
    """Captura/coleta"""
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

    print("[WARN] Capturando via Scapy (fallback). Pode haver perda sob alta taxa.", file=sys.stderr)
    pkts = sniff(iface=interface, timeout=duration)
    wrpcap(str(output), pkts)