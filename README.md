# AegisNet  
### Neural Network–Driven Real-Time Network Flow Anomaly Detection

AegisNet is an AI-powered anomaly detection system for network traffic, built using **PyTorch**, **FastAPI**, and an interactive **SOC-style dashboard**.  
It uses an autoencoder to score network flow behaviour in real time, helping detect suspicious or abnormal activity.

---

## 🚀 Features
- **Autoencoder-Based Anomaly Detection**  
  Learns normal network behaviour and scores deviations.

- **FastAPI Inference Server**  
  REST API for single and batch flow scoring.

- **Interactive Web Dashboard**  
  Live anomaly scores, recent flows, model device status.

- **Flow Monitoring Agent (Optional)**  
  Reads system network activity and streams it to the inference service.

- **Extensible Modular Design**  
  Swap out models, add sensors, expand UI.

---

## 📁 Project Structure
AegisNet/
│
├── aegisnet/
│ └── models/
│ └── autoencoder.py
│
├── static/
│ └── style.css
│
├── templates/
│ └── dashboard.html
│
├── inference_service.py
├── anomaly_scorer.py
├── train_autoencoder.py
├── flow_agent.py
├── requirements.txt
└── README.md


---

## 🔧 Installation

### 1. Clone the repository
```bash
git clone https://github.com/CutbackTG/AegisNet.git
cd AegisNet

2. Create a virtual environment
python -m venv .venv

3. Activate it

Windows (PowerShell):

.\.venv\Scripts\Activate.ps1


macOS/Linux:

source .venv/bin/activate

4. Install dependencies
pip install -r requirements.txt

🤖 Training the Autoencoder

To train a fresh AegisNet model:

python train_autoencoder.py


This will generate:

autoencoder.pt


Which contains:

Model weights

Feature list

Normalization mean & std

Input dimensions

⚡ Running the Inference Server

Start the backend + dashboard:

uvicorn inference_service:app --reload --port 8000


Open the dashboard:

http://127.0.0.1:8000

🛰️ REST API Usage
Score a single flow
curl -X POST http://127.0.0.1:8000/score \
  -H "Content-Type: application/json" \
  -d "{\"features\": {
    \"bytes_in\": 1200,
    \"bytes_out\": 900,
    \"packets\": 22,
    \"duration\": 0.52,
    \"src_port\": 443,
    \"dst_port\": 52213,
    \"protocol\": 6
  }}"

Score multiple flows
curl -X POST http://127.0.0.1:8000/score_bulk \
  -H "Content-Type: application/json" \
  -d "{\"flows\": [...]}"

🖥️ Dashboard Screenshot

(Insert your screenshot here)

🧩 Architecture Overview
1. Autoencoder (PyTorch)

Learns normal flow behaviour.
Anomaly = high reconstruction error.

2. Anomaly Scorer

Loads model

Applies normalization

Computes anomaly scores

3. FastAPI Inference Server

Routes:

/score

/score_bulk

/ UI dashboard

/ui/score GUI form submit

4. Flow Agent

Optional background agent for real-time local monitoring.

📌 Configuration

You can adjust:

Suspicious threshold (default 0.05)

Feature set

Dashboard layout

Flow agent behaviour

🛡️ Security Notice

AegisNet is currently a prototype.
Before production use, add:

Authentication

TLS

Logging & audit trails

Replay protection

Robust error handling

🤝 Contributing

Fork the repo

Create a new branch

Commit clean changes

Open a pull request

📜 License

MIT License recommended.
