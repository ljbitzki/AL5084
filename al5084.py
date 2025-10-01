import argparse
from pathlib import Path
import cap as mCAP

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
    ap_cap.add_argument("-s", "--snaplen", type=int, default=96, help="Snaplen (bytes)")
    args = ap.parse_args()

    if args.cmd == "capture":
        mCAP.capture_pcap(args.out, args.iface, args.duration, snaplen=args.snaplen)

if __name__ == "__main__":
    main()
