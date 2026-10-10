# Autonomous Multi-Agent Cyber Defense Simulator (AMCDS)

Autonomous Multi-Agent Cyber Defense Simulator — a research platform and capstone project for modeling enterprise networks, executing dynamic adversarial attack/defense scenarios, and evaluating machine learning-driven security agents.

---

## 🌟 Overview

AMCDS provides an end-to-end cyber range environment that simulates:
- **Intelligent Adversaries**: Automated threat actors (e.g. APT-29, APT-41) executing MITRE ATT&CK tactics (Reconnaissance, Exploitation, Lateral Movement, Privilege Escalation).
- **Autonomous Defenders**: SOC agents and incident response engines executing host isolation, process termination, and credential rotation.
- **Enterprise Network Topology**: Active Directory domains, domain controllers, databases, public/internal web services, and employee workstations.
- **ML & AI Layers**: Graph Neural Network (GNN) risk exposure prediction and Large Language Model (LLM) strategic and tactical triage.
- **Interactive Web Dashboard**: React + Vite frontend and FastAPI backend for real-time visualization of network topology, live attack telemetry, and ecosystem analytics.

---

## 📁 Repository Layout

```
├── agent_framework/      # Multi-agent actors (attacker, defender, SOC roles, sysadmin, employees)
├── attack_engine/        # MITRE ATT&CK execution, attack graph analysis, blast radius calculation
├── defense_engine/       # Containment actions, automated firewalls, and zero-trust controls
├── simulation_engine/    # Network topology, event loop, cloud (AWS), k8s, and IoT simulators
├── gnn_layer/            # Graph Neural Network risk scoring (GCN / GAT models)
├── llm_orchestration/    # LLM-based strategic planning, tactical reasoning, and incident analysis
├── rl_service/           # Gym/Gymnasium environment and RL co-evolution loop
├── intelligence/         # Threat feed aggregation (NVD, CISA KEV, EPSS)
├── economics/            # Financial loss estimation and enterprise risk scoring
├── copilot/              # Security copilot and automated report generator
├── dashboard_backend/    # FastAPI REST API & simulation telemetry endpoints
├── frontend/             # Modern React 19 + Vite dashboard with interactive cyber range
├── scripts/              # CLI execution scripts and entry points
├── playbooks/            # Generated containment scripts and firewall policies
├── reports/              # Simulation execution reports and markdown logs
└── tests/                # Test suite (unit, integration, and scenario tests)
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Python**: 3.10+ (tested on Python 3.11)
- **Node.js**: v18+ (tested on Node v24)
- **Git**

### 2. Backend Setup & Dependencies

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

### 3. Frontend Setup

Install Node dependencies:

```bash
cd frontend
npm install
cd ..
```

---

## 🖥️ Running the Project

### Option A: Interactive Web Dashboard (Recommended)

1. **Start the FastAPI Backend** (in terminal 1):
   ```bash
   python -m uvicorn dashboard_backend.main:app --reload --port 8000
   ```
   API will be live at `http://127.0.0.1:8000` (Docs: `http://127.0.0.1:8000/docs`).

2. **Start the React Frontend** (in terminal 2):
   ```bash
   cd frontend
   npm run dev
   ```
   Open **[http://localhost:5173](http://localhost:5173)** in your browser to interact with the live topology, trigger attack vectors, and view threat analytics.

---

### Option B: CLI Simulations

AMCDS includes standalone CLI simulation scripts (runnable without external database dependencies):

| Script | Command | Description |
|---|---|---|
| **Quick Demo** | `python scripts/run_demo.py` | 5-tick adversary walkthrough with lateral movement, isolation, and patching |
| **Co-Evolution Loop** | `python scripts/run_simulation.py` | 30-tick adversary vs defender loop; writes `reports/simulation_report.md` |
| **Intelligence Platform** | `python scripts/run_intelligence_demo.py` | GNN risk path prediction + LLM strategic planner showcase |
| **Interactive Cyber Range** | `python scripts/run_interactive_cyber_range.py` | Interactive CLI cyber range simulator |

---

## 🧪 Running Tests

Run the test suite using pytest:

```bash
python -m pytest tests/test_dashboard.py
python -m pytest tests/
```

---

## 🐳 Optional Infrastructure (Docker Compose)

To spin up enterprise storage services (PostgreSQL, Neo4j, Redis, Kafka, ClickHouse):

```bash
docker compose up -d
```

Copy `.env.example` to `.env` to configure connection strings if connecting to live database containers:

```bash
cp .env.example .env
```

---

## 📄 License & Academic Attribution
Developed for capstone research in autonomous cyber defense systems, multi-agent reinforcement learning, and automated threat mitigation.