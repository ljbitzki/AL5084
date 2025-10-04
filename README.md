# AL5084
Disciplina de Desenvolvimento de Software PPGES Unipampa

#### Ambiente de desenvolvimento (apenas para referência):
- Sistema Operacional do hospedeiro: Kubuntu Desktop 24.04 LTS
  - Processador AMD Ryzen 5 5600X
  - 32GB de memória RAM
  - GPU GeForce RTX 3070Ti 8GB de memória VRAM
  - Oracle VirtualBox 7.1.4

- Sistema Operacional da VM de desenvolvimento: Ubuntu Server 22.04 LTS
  - 6 vCPU com PAE/NX
  - 8GB de memória RAM
  - 64MB de memória VRAM

#### Instalação de dependências e ajustes em nível de Sistema Operacional (pacotes)
```
sudo apt update
sudo apt install tshark tcpdump python3-venv wireshark git -y
sudo dpkg-reconfigure wireshark-common
sudo chmod +x /usr/bin/dumpcap
```
Os comandos `sudo dpkg-reconfigure wireshark-common` e `sudo chmod +x /usr/bin/dumpcap` são necessários para possibilitar a captura de pacotes através do usuário corrente, sem a necessidade da execução como `root`.

#### Clonar o repositório, iniciar um ambiente virtual e instalar os pacotes Python necessários com o gerenciador `pip`
```
git clone https://github.com/ljbitzki/AL5084.git
cd AL5084/ || exit 1
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Execução de uma captura/coleta de tráfego
```
python al5084.py capture -i enp0s3 -d 10 -o captures/
```

##### Parâmetros:
- `capture`: Seletor de comando da CLI para acionar a camada de captura/coleta.
- `-i` ou `--iface`: Interface de rede para a captura/coleta (ex: eth0, enp0s3, etc).
- `-d` ou `--duration`: Tempo em que a captura será encerrada automaticamente (em segundos).
- `-o` ou `--outdir`: Diretório/nome_do_arquivo_desejado.pcap de saída.
- `-s` ou `--snaplen` (opcional): Valor em bytes do snapshot. Ver mais em [SnapLen](https://wiki.wireshark.org/SnapLen).

#### Execução da extração automatizada de fluxos/features de uma coleta
```
python al5084.py features -p captures/arquivo_armazenado.pcap -o features/
```

##### Parâmetros:
- `features`: Seletor de comando da CLI para acionar a camada de extração de fluxos/features.
- `-p` ou `--pcap`: Arquivo .pcap a ser analisado.
- `-o` ou `--outdir`: Diretório de saída das extrações.

#### Estrutura (teórica) deste repositório

```
projeto_dessoft/
├── al5084.py          # Aplicação principal com CLI para execução de todas as funcionalidades
├── cap.py             # Funções relativas ao módulo de captura
├── feat.py            # Funções relativas ao módulo de extração de features
├── ds.py              # Funções relativas ao módulo de geração de datasets
├── ml.py              # Funções relativas ao módulo de treinamento de Machine Learning
├── pred.py            # Funções relativas ao módulo de geração de relatório de predições
├── captures/          # Diretório com arquivos .pcap de captura (PCAP)
├── features/          # Diretório de CSVs de features extraídas (CSV)
├── datasets/          # Diretório de datasets consolidados rotulados (CSV)
├── models/            # Diretório de treinamentos de modelos
└── predictions/       # Diretório de relatórios de predição (CSV)
```

[Documentação do andamento disponível na Wiki do repositório.](https://github.com/ljbitzki/AL5084/wiki)
