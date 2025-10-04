"""..."""
import argparse
from pathlib import Path
import cap as mCAP
import feat as mFEAT

def main():
    """Função principal"""
    ap = argparse.ArgumentParser(
        prog="al5084",
        description="Pipeline de captura, extração de features, geração de dataset e ML para tráfego de rede.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_cap = sub.add_parser("capture", help="Capturar PCAP de uma interface")
    ap_cap.add_argument("-i", "--iface", required=True, help="Interface (ex: enp0s3, eth0, etc)")
    ap_cap.add_argument("-d", "--duration", type=int, default=60, help="Duração (s)")
    ap_cap.add_argument("-o", "--outdir", required=True, type=Path, help="Direório de saída dos arquivos .pcap")
    ap_cap.add_argument("-s", "--snaplen", type=int, default=96, help="Snaplen (bytes)")

    ap_feat = sub.add_parser("features", help="Extrair features de um PCAP")
    ap_feat.add_argument("-p", "--pcap", required=True, type=Path, help="Arquivos .pcap para extração")
    ap_feat.add_argument("-o", "--outdir", required=True, type=Path, help="Direório de saída dos arquivos .csv")

    args = ap.parse_args()

    if args.cmd == "capture":
        mCAP.capture_pcap(args.out, args.iface, args.duration, snaplen=args.snaplen)

    if args.cmd == "features":
        out_csvs = mFEAT.extract_features(args.pcap, args.outdir)
        print("\n".join(map(str, out_csvs)))

if __name__ == "__main__":
    main()
