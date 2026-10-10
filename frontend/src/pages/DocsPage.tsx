import { useState } from "react";
import { motion } from "framer-motion";
import { ChevronDown, ChevronRight, Terminal, Server, Cpu, Globe, FileText, Zap } from "lucide-react";
import PageTransition from "../components/PageTransition";

const fadeUpVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 1.0, ease: [0.16, 1, 0.3, 1] as any } },
};

interface DocSection {
  id: string;
  title: string;
  icon: any;
  content: { heading: string; body: string; code?: string }[];
}

const sections: DocSection[] = [
  {
    id: "overview",
    title: "System Overview",
    icon: Globe,
    content: [
      {
        heading: "What is AMCDS?",
        body: "The Autonomous Multi-Agent Cyber Defense Simulator (AMCDS) is a co-evolutionary simulation platform where autonomous attacker and defender agents compete in a realistic enterprise network environment. The system uses reinforcement learning, graph neural networks, and large language models to create intelligent cybersecurity simulations.",
      },
      {
        heading: "Core Architecture",
        body: "AMCDS follows a modular micro-service architecture with the following layers:",
        code: `Defense_System/
  ├── agent_framework/    # Base attacker/defender agent classes
  ├── attack_engine/      # Attack execution (exploit, lateral move, etc.)
  ├── defense_engine/     # Defense execution (isolate, patch, etc.)
  ├── gnn_layer/          # Graph Neural Network risk predictor
  ├── llm_orchestration/  # LLM-powered strategic reasoning
  ├── rl_service/         # Reinforcement learning environment
  ├── simulation_engine/  # Network topology & simulation core
  ├── telemetry_service/  # Event streaming & log ingestion
  ├── dashboard_backend/  # FastAPI REST API server
  └── frontend/           # React + Vite dashboard UI`,
      },
    ],
  },
  {
    id: "api",
    title: "API Reference",
    icon: Terminal,
    content: [
      {
        heading: "POST /api/run",
        body: "Execute a full simulation run. Returns topology state, tick-by-tick logs, and final metrics.",
        code: `# Request
POST http://127.0.0.1:8000/api/run?mode=standard
POST http://127.0.0.1:8000/api/run?mode=intelligent

# Response Schema
{
  "run_id": "uuid-string",
  "hosts": [{ "id": "DC-01", "ip": "10.0.1.2", "compromised": false, ... }],
  "connections": [{ "source": "WS-01", "target": "WEB-02" }],
  "metrics": {
    "total_nodes": 10,
    "compromised_nodes": 3,
    "protection_score": 70,
    "attacker_reward": 12.5,
    "defender_reward": 8.3
  },
  "logs": [{ "tick": 1, "events": [...] }]
}`,
      },
      {
        heading: "GET /health",
        body: "Health check endpoint. Returns { \"status\": \"healthy\" } when the backend is operational.",
        code: `curl http://127.0.0.1:8000/health
# Response: {"status":"healthy"}`,
      },
    ],
  },
  {
    id: "deployment",
    title: "Deployment Guide",
    icon: Server,
    content: [
      {
        heading: "Local Development",
        body: "Start both the backend API server and frontend dev server:",
        code: `# Terminal 1: Start FastAPI backend
cd Defense_System
python -m uvicorn dashboard_backend.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Start Vite frontend
cd Defense_System/frontend
npm install
npm run dev

# Open http://localhost:5173 in your browser`,
      },
      {
        heading: "Docker Deployment",
        body: "Use Docker Compose for containerized deployment with all services:",
        code: `# Build and run all services
docker-compose up --build

# Services will be available at:
# - Frontend: http://localhost:5173
# - Backend API: http://localhost:8000
# - Neo4j: bolt://localhost:7687
# - Redis: localhost:6379`,
      },
      {
        heading: "Production Build",
        body: "Create an optimized production build of the frontend:",
        code: `cd frontend
npm run build
# Output will be in frontend/dist/
# Serve with any static file server (nginx, etc.)`,
      },
    ],
  },
  {
    id: "simulation",
    title: "Simulation Modes",
    icon: Cpu,
    content: [
      {
        heading: "Standard Mode",
        body: "Runs a 30-tick simulation with 10 network hosts. Attacker and defender agents use rule-based strategies with reinforcement learning reward signals. The attacker performs reconnaissance, exploitation, and lateral movement. The defender responds with isolation and patching.",
      },
      {
        heading: "Intelligent Mode",
        body: "Runs a 10-tick simulation enhanced with GNN risk prediction and LLM-orchestrated decision making. The GNN identifies highest-risk nodes, the Strategic Planner LLM selects attack targets, and the Incident Analysis LLM triages alerts and selects defensive responses.",
      },
    ],
  },
  {
    id: "realworld",
    title: "Real-World Integration",
    icon: Zap,
    content: [
      {
        heading: "Data Ingestion",
        body: "Import real network data from Nessus XML/CSV scans, Asset Inventory CSVs, and BloodHound JSON exports using the RealWorldIngestor module.",
        code: `from simulation_engine.ingestor import RealWorldIngestor

ingestor = RealWorldIngestor()

# Import from Nessus scan
hosts = ingestor.from_nessus_csv("scan_results.csv")

# Import from asset inventory
hosts = ingestor.from_asset_csv("inventory.csv")

# Import from BloodHound
hosts = ingestor.from_bloodhound_json("bloodhound.json")`,
      },
      {
        heading: "Active Mitigation",
        body: "Generate firewall quarantine commands and Ansible playbooks for real-world incident response. By default runs in dry_run mode — set dry_run=False to execute live commands.",
        code: `from defense_engine.real_world_mitigation import RealWorldMitigationRunner

runner = RealWorldMitigationRunner(dry_run=True)  # Safe mode
runner.quarantine_host("10.0.1.5")     # Generates netsh/iptables commands
runner.generate_playbook("WS-01", "isolate_host")  # Creates Ansible YAML`,
      },
      {
        heading: "Live Scanning",
        body: "Perform TCP port scanning and banner grabbing against live hosts using the RealWorldScanner module.",
        code: `from attack_engine.real_world_scanner import RealWorldScanner

scanner = RealWorldScanner()
results = scanner.tcp_scan("10.0.1.5", ports=[22, 80, 443, 445, 3306])`,
      },
    ],
  },
  {
    id: "config",
    title: "Configuration",
    icon: FileText,
    content: [
      {
        heading: "Environment Variables",
        body: "Configure external service connections and LLM API keys:",
        code: `# LLM API Keys (optional - uses mock responses by default)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=AIza...

# Database Connections (optional - uses in-memory by default)
NEO4J_URI=bolt://localhost:7687
REDIS_URL=redis://localhost:6379
CLICKHOUSE_HOST=localhost`,
      },
      {
        heading: "Network Topology",
        body: "Customize the simulation network by modifying the topology setup in dashboard_backend/main.py. Add hosts, services, vulnerabilities, and connections to model your specific environment.",
      },
    ],
  },
];

export default function DocsPage() {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(["overview"]));

  const toggleSection = (id: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <PageTransition>
      <div className="p-6 md:p-10 max-w-[1000px] mx-auto">
        {/* Header */}
        <div className="mb-10">
          <span className="text-[10px] tracking-[0.3em] uppercase text-[#00f5d4] mb-2 block font-medium">
            Reference Manual
          </span>
          <h1 className="font-serif text-3xl md:text-5xl tracking-wide font-extralight text-white mb-3">
            Documentation
          </h1>
          <p className="text-sm text-white/60 font-light leading-relaxed max-w-2xl">
            Complete system documentation including architecture overview, API reference,
            deployment guides, and real-world integration patterns.
          </p>
        </div>

        {/* Table of Contents */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
          <div className="glassmorphism-card rounded-2xl p-6 mb-8">
            <h3 className="text-[10px] tracking-[0.3em] uppercase text-white/40 mb-4 font-semibold">Table of Contents</h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {sections.map((section) => {
                const Icon = section.icon;
                return (
                  <button
                    key={section.id}
                    onClick={() => {
                      setExpandedSections(prev => new Set(prev).add(section.id));
                      document.getElementById(`doc-${section.id}`)?.scrollIntoView({ behavior: "smooth" });
                    }}
                    className="flex items-center gap-2 text-left text-[11px] text-white/60 hover:text-white/90 transition-colors p-2 rounded-lg hover:bg-white/[0.03] cursor-pointer"
                  >
                    <Icon size={12} className="text-[#00f5d4]/60" />
                    <span>{section.title}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </motion.div>

        {/* Doc Sections */}
        <div className="space-y-4">
          {sections.map((section) => {
            const Icon = section.icon;
            const isExpanded = expandedSections.has(section.id);
            return (
              <motion.div
                key={section.id}
                id={`doc-${section.id}`}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true, margin: "-30px" }}
                variants={fadeUpVariants}
                className="glassmorphism-card rounded-2xl overflow-hidden"
              >
                <button
                  onClick={() => toggleSection(section.id)}
                  className="w-full flex items-center justify-between p-6 text-left cursor-pointer hover:bg-white/[0.02] transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <Icon size={18} className="text-[#00f5d4]/70" />
                    <h2 className="text-base font-light text-white tracking-wider">{section.title}</h2>
                  </div>
                  {isExpanded ? <ChevronDown size={16} className="text-white/40" /> : <ChevronRight size={16} className="text-white/40" />}
                </button>

                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    transition={{ duration: 0.3 }}
                    className="px-6 pb-6 space-y-6"
                  >
                    {section.content.map((block, bIdx) => (
                      <div key={bIdx} className="border-l-2 border-white/10 pl-5">
                        <h3 className="text-sm font-semibold text-white/90 mb-2 tracking-wide">{block.heading}</h3>
                        <p className="text-xs text-white/55 leading-relaxed font-light mb-3">{block.body}</p>
                        {block.code && (
                          <div className="bg-[#05070a] border border-white/5 rounded-xl p-4 overflow-x-auto">
                            <pre className="text-[10px] font-mono text-white/70 leading-relaxed whitespace-pre">{block.code}</pre>
                          </div>
                        )}
                      </div>
                    ))}
                  </motion.div>
                )}
              </motion.div>
            );
          })}
        </div>
      </div>
    </PageTransition>
  );
}
