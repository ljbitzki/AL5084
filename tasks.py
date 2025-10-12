from celery import Celery
from cap import capture_pcap
from feat import extract_features
from ds import build_dataset
from pathlib import Path

app = Celery("tasks")
app.config_from_object("celeryconfig")

@app.task
def run_capture_task(output, interface, duration, snaplen):
    """Task Celery para executar captura"""
    result_cap = capture_pcap(Path(output), interface, duration, snaplen)
    return result_cap

@app.task
def run_features_task(pcap, output):
    """Task Celery para executar extração de features"""
    result_feat = extract_features(Path(pcap), Path(output))
    return str(result_feat)

@app.task
def run_datasets_task(csvs, output, labels, default_label):
    """Task Celery para executar geração de datasets"""
    csvs_list = []
    csvs_list.append(csvs)
    result_ds = build_dataset(csvs_list, Path(output), labels, default_label)
    return str(result_ds)