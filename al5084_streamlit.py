import glob
import os
import sys
import cap as mCAP
import feat as mFEAT
import streamlit as st
import sys
from pathlib import Path

def main():
    st.set_page_config(page_title="AL5084 - Disciplina de Desenvolvimento de Software PPGES Unipampa", page_icon="")
    st.title("AL5084 - Disciplina de Desenvolvimento de Software PPGES Unipampa")
    
    command = st.sidebar.selectbox("Selecione o comando", ["capture", "features"])
    
    if command == "capture":
        st.header("Captura/coleta de tráfego")
        
        c_outdir = st.text_input("Diretório/ de saída do arquivo .pcap", value="captures/" ,placeholder="captures/", key="c_outdir")
        duration = st.number_input("Tempo em que a captura será encerrada automaticamente (em segundos)", value=10, min_value=1, key="duration")
        iface = st.text_input("Interface de rede para a captura/coleta (ex: eth0, enp0s3, etc)", value="enp0s3", placeholder="enp0s3", key="iface")        
        snaplen = st.number_input("SnapLen (em bytes)", value=96, min_value=1, key="snaplen")
        if st.button("Executar captura", type="primary"):
            if not c_outdir:
                st.error("Necessário informar o diretório de saída do arquivo .pcap!")
            if not iface:
                st.error("Necessário informar a interface para a captura/coleta!")
            else:
                with st.spinner(f'Executando a captura da interface {iface} por {duration} segundos no diretório {c_outdir} com SnapLen de {snaplen} bytes.'):
                    out_pcap = mCAP.capture_pcap(Path(c_outdir), iface, duration, snaplen=snaplen)
                    st.write(out_pcap)
                st.success("Captura concluída!")
    
    elif command == "features":
        st.header("Extrair features/fluxos de um PCAP")
        
        o_dir = Path('captures/')
        captures = o_dir.glob('*.pcap')
        last_pcap = max(captures, key=os.path.getctime)

        col1, col2 = st.columns(2)
        with col1:
            pcap = st.text_input("Arquivo de captura .pcap", value=last_pcap, placeholder=last_pcap, key="pcap")
        with col2:
            f_outdir = st.text_input("Diretório de saída dos arquivos .csv", value="features/", placeholder="features/", key="f_outdir")
        
        if st.button("Extecutar extração", type="primary"):
            if not pcap or not f_outdir:
                st.error("Obrigatório informar um arquivo .pcap válido e um diretório de saída!")
            else:
                with st.spinner(f'Executando a extração de features/fluxos do {pcap} no diretório {f_outdir}'):
                    out_csvs = mFEAT.extract_features(Path(pcap), Path(f_outdir))
                    st.write(f"\n".join(map(str, out_csvs)))
                st.success("Extração concluída!")

if __name__ == "__main__":
    main()