import glob
import os
import time
import sys
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
    
    command = st.sidebar.selectbox("Comandos de captura/extração", ["Captura/Coleta", "Features/Fluxos", "Geração de Datasets"])
    
    if command == "Captura/Coleta":
        st.header("Captura/coleta de tráfego")
        
        c_outdir = st.text_input("Diretório/ de saída do arquivo .pcap", value="captures/" ,placeholder="captures/", key="c_outdir")
        duration = st.number_input("Tempo em que a captura será encerrada automaticamente (em segundos)", value=5, min_value=1, key="duration")
        iface = st.text_input("Interface de rede para a captura/coleta (ex: eth0, enp0s3, etc)", value="enp0s3", placeholder="enp0s3", key="iface")        
        snaplen = st.number_input("SnapLen (em bytes)", value=96, min_value=1, key="snaplen")
        if st.button("Executar captura", type="primary"):
            if not c_outdir:
                st.error("Necessário informar o diretório de saída do arquivo .pcap!")
            if not iface:
                st.error("Necessário informar a interface para a captura/coleta!")
            else:
                task = run_capture_task.delay(c_outdir, iface, duration, snaplen)
                st.session_state["task_id"] = task.id
                st.session_state["start_time"] = time.time()
                st.session_state["progress"] = 0
                st.success(f"Tarefa Celery iniciada! ID: `{task.id}`")

        if "task_id" in st.session_state:
            task_id = st.session_state["task_id"]
            task_result = AsyncResult(task_id, app=celery_app)
            duration = st.session_state.get("duration", 10)
            start_time = st.session_state.get("start_time", time.time())

            st.markdown(f"#### Status da tarefa ID: `{task_id}`")
            st.info(task_result.status)

            progress_bar = st.progress(st.session_state.get("progress", 0))
            elapsed = time.time() - start_time
            remaining = max(duration - elapsed, 0)
            progress = min(int((elapsed / duration) * 100), 99)

            if task_result.status not in ["SUCCESS", "FAILURE"]:
                st.session_state["progress"] = progress
                progress_bar.progress(progress)
                st.info(f"Tempo restante estimado: {int(remaining)}s")
                st_autorefresh(interval=1000, limit=None, key="status_poll")

            else:
                if task_result.successful():
                    st.session_state["progress"] = 100
                    progress_bar.progress(100)
                    output_file = task_result.get()
                    st.success(f"Captura concluída! Arquivo salvo em: `{output_file}`")
                else:
                    st.error("Falha na execução da captura.")

                st.session_state.pop("task_id", None)
                st.session_state.pop("progress", None)
                st.session_state.pop("start_time", None)
                st.session_state.pop("duration", None)

    elif command == "Features/Fluxos":
        st.header("Extrair features/fluxos de um PCAP")
        
        o_dir = Path('captures/')
        captures = o_dir.glob('*.pcap')
        last_pcap = max(captures, key=os.path.getctime)

        col1, col2 = st.columns(2)
        with col1:
            pcap = st.text_input("Arquivo de captura .pcap (último)", value=last_pcap, placeholder=last_pcap, key="pcap")
        with col2:
            f_outdir = st.text_input("Diretório de saída dos arquivos .csv", value="features/", placeholder="features/", key="f_outdir")
        
        if st.button("Executar extração", type="primary"):
            if not pcap or not f_outdir:
                st.error("Obrigatório informar um arquivo .pcap válido e um diretório de saída!")
            else:
                with st.spinner(f'Executando a extração de features/fluxos do {pcap} no diretório {f_outdir}'):
                    task = run_features_task.delay(pcap, f_outdir)
                    st.success(f"Extração iniciada. `{task.id}`")
                    st.session_state["task_id"] = task.id
                    task_id = st.session_state["task_id"]
                    task_result = AsyncResult(task_id, app=celery_app)

        if "task_id" in st.session_state:
            task_id = st.session_state["task_id"]
            task_result = AsyncResult(task_id, app=celery_app)

            st.write(f"#### Status da tarefa ID: `{task_id}`")
            st.info(task_result.status)

            if task_result.status not in ["SUCCESS", "FAILURE"]:
                st_autorefresh(interval=500, limit=None, key="extract_poll")

            elif task_result.successful():
                output_files = task_result.get()
                st.success(f"Extração concluída! Arquivos salvos em **`features/`**:")
                st.session_state.pop("task_id", None)
            else:
                st.error("Falha na extração!")
                st.session_state.pop("task_id", None)

    elif command == "Geração de Datasets":
        st.header("Geração de Datasets")

        ds_dir = Path('features/')
        list_csvs = ds_dir.glob('*.csv')
        csv_files = [str(f) for f in list_csvs]
        selected_file = st.selectbox("Selecione o arquivo CSV para ser processado:", csv_files)
        ds_outdir = st.text_input("Diretório de saída dos datasets", value="datasets/", placeholder="datasets/", key="ds_outdir")
        labels = st.text_input("Selecione o arquivo CSV com os rótulos:", value="labels.csv", placeholder="labels.csv", key="labels")
        default_label = st.text_input("Digite o rótulo padrão para fluxos sem rótulo:", value="SUSPECT", placeholder="SUSPECT/OK", key="default_label")

        if st.button("Geração de dataset", type="primary"):
            if not ds_outdir or not labels or not default_label:
                st.error("Obrigatório informar valores válidos em todos os campos!")
            else:
                with st.spinner(f'Executando a geração de dataset com base no arquivo {selected_file} no diretório {ds_dir}'):
                    task = run_datasets_task.delay(selected_file, ds_outdir, labels, default_label)
                    st.success(f"Geração de dataset iniciada. `{task.id}`")
                    st.session_state["task_id"] = task.id
                    task_id = st.session_state["task_id"]
                    task_result = AsyncResult(task_id, app=celery_app)

        if "task_id" in st.session_state:
            task_id = st.session_state["task_id"]
            task_result = AsyncResult(task_id, app=celery_app)

            st.write(f"#### Status da tarefa ID: `{task_id}`")
            st.info(task_result.status)

            if task_result.status not in ["SUCCESS", "FAILURE"]:
                st_autorefresh(interval=500, limit=None, key="extract_poll")

            elif task_result.successful():
                output_files = task_result.get()
                st.success(f"Geração de dataset concluída! Arquivo salvo em **`datasets/`**:")
                st.session_state.pop("task_id", None)
            else:
                st.error("Falha na geração!")
                st.session_state.pop("task_id", None)

if __name__ == "__main__":
    main()