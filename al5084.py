"""CLI"""
import argparse
import cap as mCAP
from pathlib import Path
from tasks import (
    run_capture_task,
    run_features_task,
    run_datasets_task,
    run_ml_anomaly_task
)
from celery.result import AsyncResult
from celery import Celery
from celery import chain


def main():
    """Main function"""
    ap = argparse.ArgumentParser(
        prog="al5084",
        description="Pipeline for capture, feature extraction, dataset generation, and ML for network traffic.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_pl = sub.add_parser("continuous", help="Continuously capture PCAP from an interface and extrac features")
    ap_pl.add_argument("-i", "--iface", required=True, help="Interface (ex: enp0s3, eth0, etc)")
    ap_pl.add_argument("-d", "--duration", type=int, default=60, help="Duration (s)")
    ap_pl.add_argument("-o", "--outdir", required=True, help="Output directory for .pcap files")
    ap_pl.add_argument("-s", "--snaplen", type=int, default=96, help="Snaplen (bytes)")

    ap_cap = sub.add_parser("capture", help="Capture PCAP from an interface")
    ap_cap.add_argument("-i", "--iface", required=True, help="Interface (ex: enp0s3, eth0, etc)")
    ap_cap.add_argument("-d", "--duration", type=int, default=60, help="Duration (s)")
    ap_cap.add_argument("-o", "--outdir", required=True, help="Output directory for .pcap files")
    ap_cap.add_argument("-s", "--snaplen", type=int, default=96, help="Snaplen (bytes)")

    ap_feat = sub.add_parser("features", help="Extract features from a PCAP")
    ap_feat.add_argument("-p", "--pcap", required=True, help=".pcap files for extraction")
    ap_feat.add_argument("-o", "--outdir", required=True, help="Output directory for .csv files")

    ap_ds = sub.add_parser("build-ds", help="Consolidate feature CSVs into final dataset")
    ap_ds.add_argument("-c", "--csvs", required=True, help="Feature CSV List")
    ap_ds.add_argument("-o", "--outdir", help="Output CSV dataset")
    ap_ds.add_argument("-l", "--labels", default=None, help="Labels CSV (flow_id,label ou 5-tupla+label)")
    ap_ds.add_argument("--default-label", type=str, default=None, help="Default label (ex: OK/SUSPECT)")

    ap_ml = sub.add_parser("machine-learning", help="Run IsolationForest ML from a dataset")
    ap_ml.add_argument("-d", "--dataset", required=True, help="Dataset CSV File")
    ap_ml.add_argument("-m", "--outdir", default="models",  help="Output model directory")
    ap_ml.add_argument("-s", "--scoredir", default="datasets", help="Output score directory")
    ap_ml.add_argument("-c", "--contamination", default=0.05, help="~5% of expected flows are anomalous.")

    ap_pipeline = sub.add_parser("pipeline", help="Extract features from a PCAP and generate unsupervised datasets")
    ap_pipeline.add_argument("-p", "--pcap", required=True, help=".pcap files for extraction")
    args = ap.parse_args()

    if args.cmd == "continuous":
        while True:
            workflow = chain(
                run_capture_task.s(args.outdir, args.iface, args.duration, snaplen=args.snaplen),
                run_features_task.s(args.pcap, 'features/'),
                run_datasets_task.s('datasets/'),
                run_ml_anomaly_task.s("models", "datasets", 0.05)
            )
            result_async = workflow.delay()
            print(f"Task Continuous, ID: ", workflow)

    if args.cmd == "capture":
        task = run_capture_task.delay(args.outdir, args.iface, args.duration, snaplen=args.snaplen)
        print(f"Task capture, ID: ", task)

    if args.cmd == "features":
        task = run_features_task.delay(args.pcap, args.outdir)
        print(f"Task features, ID: ", task)

    if args.cmd == "build-ds":
        task = run_datasets_task.delay(args.csvs)
        print(f"Task dataset, ID: ", task)

    if args.cmd == "machine-learning":
        task = run_ml_anomaly_task.delay(args.dataset, args.outdir, args.scoredir, args.contamination)
        print(f"Task ML, ID: ", task)

    elif args.cmd == "pipeline":
        workflow = chain(
            run_features_task.s(args.pcap, 'features/'),
            run_datasets_task.s('datasets/'),
            run_ml_anomaly_task.s('models', 'datasets', 0.05)
        )
        result_async = workflow.delay()
        print(f"Task Pipeline, ID: ", result_async)

if __name__ == "__main__":
    main()
