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
    """
    Celery Task to perform capture. Four arguments expected:
    Output directory, which can be a relative or an absolute path;
    A valid network interface from the running host. This network interface must have an IP address;
    An integer representing the number of seconds the capture will last before automatically ending;
    An integer representing the snapshot length, which is the maximum number of bytes will save from each packet.

    Args:
        output (string): Output path
        interface (string): Interface name
        duration (int): Duration in seconds
        snaplen (int): Snapshot lenght

    Returns:
        result_cap (string): Capture file
    """    

    result_cap = capture_pcap(Path(output), interface, duration, snaplen)
    return str(result_cap)

@app.task
def run_features_task(pcap, output):
    """
    Celery Task to perform feature extraction. Two arguments expected:
    A .pcap file to be processed, which can be a relative or an absolute path;
    Output directory, which can be a relative or an absolute path.

    Args:
        pcap (string): Capture file
        output (string): Output path

    Returns:
        pcap(Path), output(Path): Path to pcap file and path to output
    """

    result_feat = extract_features(Path(pcap), Path(output))
    return [str(p) for p in result_feat]

@app.task
def run_datasets_task(feature_csvs, outdir="datasets/"):
    """
    Celery Task to perform dataset generation. One argument expected:
    A directory with .csvs files previously extracted, which can be a relative or an absolute path.

    Args:
        feature_csvs (Path): csv files path
        outdir (str, optional): Dataset output directory. Defaults to "datasets/".

    Returns:
        df(string): Pandas DataFrame
    """

    paths = [Path(p) for p in feature_csvs]
    df = build_dataset_unsupervised(paths, outdir=outdir, save=True)
    return str(df)

@app.task
def run_ml_anomaly_task(dataset_csv, models_dir="models/", scores_dir="datasets/", contamination=0.05):
    """
    Celery Task to perform IsolationForest ML in a dataset. One argument expected:
    A directory with .csvs files previously generated, which can be a relative or an absolute path.

    Args:
        dataset_csv (string): Input dataset csv file
        models_dir (str, optional): Models directory. Defaults to "models/".
        scores_dir (str, optional): Model score directory. Defaults to "datasets/".
        contamination (float, optional): IsolationForest contamination. Defaults to 0.05.

    Returns:
        run_anomaly_detection (Dict[str, Any]: Train results): Train results
    """    

    from ml import run_anomaly_detection
    return run_anomaly_detection(
        dataset_path=dataset_csv,
        models_dir=models_dir,
        scores_dir=scores_dir,
        contamination=contamination,
    )