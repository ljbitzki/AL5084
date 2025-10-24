import glob
import os
import time
import sys
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from pathlib import Path
from tasks import run_capture_task, run_features_task, run_datasets_task
from celery.result import AsyncResult
from celery import Celery

celery_app = Celery("tasks")
celery_app.config_from_object("celeryconfig")

def main():
    st.set_page_config(page_title="AL5084 - Disciplina de Desenvolvimento de Software PPGES Unipampa", page_icon="")
    st.title("AL5084 - Disciplina de Desenvolvimento de Software PPGES Unipampa")
    
    command = st.sidebar.selectbox("Aavailable Commands", ["Capture", "Features/Flows", "View Features/Flows", "Dataset Generation"])
    
    if command == "Capture":
        st.header("Capture")
        
        c_outdir = st.text_input(".pcap file output directory", value="captures/" ,placeholder="captures/", key="c_outdir")
        duration = st.number_input("Ttime at which the capture will automatically end (in seconds)", value=5, min_value=1, key="duration")
        iface = st.text_input("Network interface for capture/collection (ex: eth0, enp0s3, etc)", value="enp0s3", placeholder="enp0s3", key="iface")        
        snaplen = st.number_input("SnapLen (in bytes)", value=96, min_value=1, key="snaplen")
        if st.button("Run capture", type="primary"):
            if not c_outdir:
                st.error("It is necessary to inform the output directory of the .pcap file!")
            if not iface:
                st.error("It is necessary to inform the interface for capture")
            else:
                task = run_capture_task.delay(c_outdir, iface, duration, snaplen)
                st.session_state["task_id"] = task.id
                st.session_state["start_time"] = time.time()
                st.session_state["progress"] = 0
                st.success(f"Celery task started! ID: `{task.id}`")

        if "task_id" in st.session_state:
            task_id = st.session_state["task_id"]
            task_result = AsyncResult(task_id, app=celery_app)
            duration = st.session_state.get("duration", 10)
            start_time = st.session_state.get("start_time", time.time())

            st.markdown(f"#### Task status ID: `{task_id}`")
            st.info(task_result.status)

            progress_bar = st.progress(st.session_state.get("progress", 0))
            elapsed = time.time() - start_time
            remaining = max(duration - elapsed, 0)
            progress = min(int((elapsed / duration) * 100), 99)

            if task_result.status not in ["SUCCESS", "FAILURE"]:
                st.session_state["progress"] = progress
                progress_bar.progress(progress)
                st.info(f"Estimated time remaining: {int(remaining)}s")
                st_autorefresh(interval=1000, limit=None, key="status_poll")

            else:
                if task_result.successful():
                    st.session_state["progress"] = 100
                    progress_bar.progress(100)
                    output_file = task_result.get()
                    st.success(f"Capture completed! File saved in: `{output_file}`")
                else:
                    st.error("Capture execution failed.")

                st.session_state.pop("task_id", None)
                st.session_state.pop("progress", None)
                st.session_state.pop("start_time", None)
                st.session_state.pop("duration", None)

    elif command == "Features/Flows":
        st.header("Extract features/flows from a .pcap")
        
        o_dir = Path('captures/')
        captures = o_dir.glob('*.pcap')
        last_pcap = max(captures, key=os.path.getctime)

        col1, col2 = st.columns(2)
        with col1:
            pcap = st.text_input(".pcap capture file (last)", value=last_pcap, placeholder=last_pcap, key="pcap")
        with col2:
            f_outdir = st.text_input("Output directory for .csv files", value="features/", placeholder="features/", key="f_outdir")
        
        if st.button("Run extraction", type="primary"):
            if not pcap or not f_outdir:
                st.error("It is mandatory to provide a valid .pcap file and an output directory!")
            else:
                with st.spinner(f'Running {pcap} feature/flow extraction in the directory {f_outdir}'):
                    task = run_features_task.delay(pcap, f_outdir)
                    st.success(f"Extraction started. `{task.id}`")
                    st.session_state["task_id"] = task.id
                    task_id = st.session_state["task_id"]
                    task_result = AsyncResult(task_id, app=celery_app)

        if "task_id" in st.session_state:
            task_id = st.session_state["task_id"]
            task_result = AsyncResult(task_id, app=celery_app)

            st.write(f"#### Task status ID: `{task_id}`")
            st.info(task_result.status)

            if task_result.status not in ["SUCCESS", "FAILURE"]:
                st_autorefresh(interval=500, limit=None, key="extract_poll")

            elif task_result.successful():
                output_files = task_result.get()
                st.success(f"Extraction complete! Files saved in `features/`")
                st.session_state.pop("task_id", None)
            else:
                st.error("Extraction failure!")
                st.session_state.pop("task_id", None)

    elif command == "View Features/Flows":
        st.header("View Features/Flows")

        ds_dir = Path('features/')
        list_csvs = ds_dir.glob('*.csv')
        csv_files = [str(f) for f in list_csvs]
        selected_file = st.selectbox("Select the CSV file to be processed:", csv_files)
        if selected_file is not None:
            try:
                df = pd.read_csv(selected_file)
                st.dataframe(df)
            except Exception as e:
                st.error(f"Error reading CSV file: {e}")

    elif command == "Dataset Generation":
        st.header("Dataset Generation")

        ds_dir = Path('features/')
        list_csvs = ds_dir.glob('*.csv')
        csv_files = [str(f) for f in list_csvs]
        selected_file = st.selectbox("Select the CSV file to be processed:", csv_files)
        ds_outdir = st.text_input("Dataset output directory", value="datasets/", placeholder="datasets/", key="ds_outdir")
        labels = st.text_input("Select the CSV file with labels:", value="labels.csv", placeholder="labels.csv", key="labels")
        default_label = st.text_input("Enter the default label for unlabeled flows:", value="OK", placeholder="SUSPECT/OK", key="default_label")

        if st.button("Dataset Generation", type="primary"):
            if not ds_outdir or not labels or not default_label:
                st.error("It is mandatory to enter valid values in all fields.!")
            else:
                with st.spinner(f'Running dataset generation based on the file {selected_file} in the directory {ds_dir}'):
                    task = run_datasets_task.delay(selected_file, ds_outdir, labels, default_label)
                    st.success(f"Dataset generation started. `{task.id}`")
                    st.session_state["task_id"] = task.id
                    task_id = st.session_state["task_id"]
                    task_result = AsyncResult(task_id, app=celery_app)

        if "task_id" in st.session_state:
            task_id = st.session_state["task_id"]
            task_result = AsyncResult(task_id, app=celery_app)
            st.write(f"#### Task status ID: `{task_id}`")
            st.info(task_result.status)

            if task_result.status not in ["SUCCESS", "FAILURE"]:
                st_autorefresh(interval=500, limit=None, key="extract_poll")

            elif task_result.successful():
                output_files = task_result.get()
                st.success(f"Dataset generation complete! File saved in `datasets/`:")
                st.session_state.pop("task_id", None)
            else:
                st.error("Generation failure!")
                st.session_state.pop("task_id", None)

if __name__ == "__main__":
    main()