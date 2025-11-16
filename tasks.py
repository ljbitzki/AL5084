from celery import Celery
from cap import capture_pcap
from feat import extract_features
from ds import build_dataset_unsupervised
from ml import run_anomaly_detection
from pathlib import Path

app = Celery("tasks")
app.config_from_object("celeryconfig")

@app.task
def run_capture_task(output, interface, duration, snaplen):
    """Celery Task to perform capture"""
    result_cap = capture_pcap(Path(output), interface, duration, snaplen)
    return str(result_cap)

@app.task
def run_features_task(pcap, output):
    """Celery Task to perform feature extraction"""
    result_feat = extract_features(Path(pcap), Path(output))
    return [str(p) for p in result_feat]

@app.task
def run_datasets_task(feature_csvs, outdir="datasets/"):
    """Celery Task to perform dataset generation"""
    paths = [Path(p) for p in feature_csvs]
    df = build_dataset_unsupervised(paths, outdir=outdir, save=True)
    return str(df)

@app.task
def run_ml_anomaly_task(dataset_csv, models_dir="models", scores_dir="datasets", contamination=0.05):
    """Celery Task to perform IsolationForest ML in a dataset"""
    from ml import run_anomaly_detection
    return run_anomaly_detection(
        dataset_path=dataset_csv,
        models_dir=models_dir,
        scores_dir=scores_dir,
        contamination=contamination,
    )