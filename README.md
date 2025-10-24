# AL5084
Disciplina de Desenvolvimento de Software PPGES Unipampa

#### Development environment (for reference only):
- Host Operating System: Kubuntu Desktop 24.04 LTS
  - AMD Ryzen 5 5600X Processor
  - 32GB RAM
  - GeForce RTX 3070Ti GPU with 8GB VRAM
  - Oracle VirtualBox 7.1.4

- Development VM Operating System: Ubuntu Server 22.04 LTS
  - 6 vCPUs with PAE/NX
  - 8GB RAM
  - 64MB VRAM

#### Installing dependencies and tweaking at the Operating System level (packages)
```
sudo apt update
sudo apt install tshark tcpdump python3-venv wireshark redis git -y
sudo dpkg-reconfigure wireshark-common
sudo chmod +x /usr/bin/dumpcap
```
The commands `sudo dpkg-reconfigure wireshark-common` and `sudo chmod +x /usr/bin/dumpcap` are required to enable packet capture using the current user, without having to run as `root`.

#### Clone the repository, start a virtual environment and install the necessary Python packages with the manager `pip`
```
git clone https://github.com/ljbitzki/AL5084.git
cd AL5084/ || exit 1
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
git clone https://github.com/ahlashkari/NTLFlowLyzer.git
cd NTLFlowLyzer
pip install -r requirements.txt
python3 setup.py install
```

---

##### Run Celery in another terminal:

```
celery -A tasks worker --loglevel=info
```

#### Performing a traffic capture
```
python al5084.py capture -i enp0s3 -d 10 -o captures/
```
##### Parameters:
- `capture`: CLI command selector to trigger capture layer.
- `-i` ou `--iface`: Network interface for capture (ex: eth0, enp0s3, etc).
- `-d` ou `--duration`: Time at which capture will automatically end (in seconds).
- `-o` ou `--outdir`: Output directory/desired_filename.pcap.
- `-s` ou `--snaplen` (optional): Value in bytes of the snapshot. See more at [SnapLen](https://wiki.wireshark.org/SnapLen).

#### Performing automated extraction of flows/features from a capture
```
python al5084.py features -p captures/capture_file.pcap -o features/
```
##### Parameters:
- `features`: CLI command selector to trigger the flows/features extraction layer.
- `-p` ou `--pcap`: .pcap file to be analyzed.
- `-o` ou `--outdir`: Extraction output directory.

#### Executing dataset generation from a file of extracted features/flows

```
python al5084.py build-ds -c features/capture.scapyflows.csv -o datasets/ -l labels.csv --default-label OK
```

##### Parameters:
- `build-ds`: CLI command selector to trigger the dataset generation layer.
- `-c` ou `--csvs`: Feature CSV file(s)
- `-o` ou `--outdir`:Dataset output directory (default: datasets/).
- `-l` ou `--labels`: labels.csv file (flow_id,label or 5-tuple+label).
- `--default-label`: Default label (ex: OK/SUSPECT)

---

#### Using Streamlit:

##### Run Streamlit in a terminal:

```
streamlit run al5084_streamlit.py
```

##### Open the running Streamlit instance in the browser:

`http://localhost:8501`

#### - Command selector

![https://github.com/ljbitzki/AL5084/assets/sl_1.png](https://github.com/ljbitzki/AL5084/blob/main/assets/1.png)

#### - Performing a traffic capture

![https://github.com/ljbitzki/AL5084/assets/sl_1.png](https://github.com/ljbitzki/AL5084/blob/main/assets/2.png)

#### - Performing automated extraction of flows/features from a capture

![https://github.com/ljbitzki/AL5084/assets/sl_1.png](https://github.com/ljbitzki/AL5084/blob/main/assets/3.png)

#### - Flows/features viewer

![https://github.com/ljbitzki/AL5084/assets/sl_1.png](https://github.com/ljbitzki/AL5084/blob/main/assets/4.png)

#### - Executing dataset generation from a file of extracted features/flows

![https://github.com/ljbitzki/AL5084/assets/sl_1.png](https://github.com/ljbitzki/AL5084/blob/main/assets/5.png)

---

#### (Theoretical) structure of this repository

```
projeto_dessoft/
├── al5084.py          # Main application with CLI to execute all functionalities
├── cap.py             # Functions related to the capture module
├── feat.py            # Functions related to the feature extraction module
├── ds.py              # Functions related to the dataset generation module
├── ml.py              # Functions related to the Machine Learning training module
├── pred.py            # Functions related to the prediction report generation module
├── captures/          # .pcap captured files directory (PCAP)
├── features/          # Extracted features directory (CSV)
├── datasets/          # Labeled datasets directory (CSV)
├── models/            # Model training directory
└── predictions/       # Prediction reports directory (CSV)
```

[Progress documentation available on the repository Wiki.](https://github.com/ljbitzki/AL5084/wiki)
