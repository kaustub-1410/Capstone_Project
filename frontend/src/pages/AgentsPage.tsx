import { motion } from "framer-motion";
import {
  Compass, Shield, Network, Cpu, Brain, Zap, Eye, Target,
  GitBranch, Layers, Radio, Lock
} from "lucide-react";
import PageTransition from "../components/PageTransition";

const fadeUpVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 1.0, ease: [0.16, 1, 0.3, 1] as any } },
};

const agents = [
  {
    title: "Attacker Agents",
    subtitle: "APT Simulation Engine",
    color: "#ff006e",
    icon: Compass,
    desc: "Adaptive entities exploring attack paths and evolving offensive strategies through reinforcement learning.",
    capabilities: [
      { icon: Target, label: "Reconnaissance", detail: "Network scanning, port enumeration, and service fingerprinting" },
      { icon: Zap, label: "Exploitation", detail: "CVE-based vulnerability exploitation with lateral movement chains" },
      { icon: Eye, label: "Persistence", detail: "Credential harvesting, privilege escalation, and backdoor installation" },
      { icon: GitBranch, label: "Strategy Evolution", detail: "RL-driven attack path optimization through multi-episode self-play" },
    ],
  },
  {
    title: "Defender Agents",
    subtitle: "Autonomous SOC Operator",
    color: "#8338ec",
    icon: Shield,
    desc: "Autonomous systems learning detection, containment, and response behaviors in real-time.",
    capabilities: [
      { icon: Eye, label: "Threat Detection", detail: "Anomaly-based alert triaging with LLM-powered incident analysis" },
      { icon: Lock, label: "Containment", detail: "Host isolation, network segmentation, and firewall rule generation" },
      { icon: Layers, label: "Patch Management", detail: "Hot-patching vulnerabilities and rotating compromised credentials" },
      { icon: Radio, label: "Response Playbooks", detail: "Automated SOAR playbook generation with Ansible integration" },
    ],
  },
  {
    title: "GNN Risk Engine",
    subtitle: "Graph Neural Network Predictor",
    color: "#fee440",
    icon: Network,
    desc: "A living graph of users, services, assets, and trust relationships analyzed by neural networks.",
    capabilities: [
      { icon: Brain, label: "Risk Scoring", detail: "Node-level risk quantification using GAT attention mechanisms" },
      { icon: GitBranch, label: "Path Analysis", detail: "Lateral movement path prediction through graph convolutions" },
      { icon: Layers, label: "Centrality Detection", detail: "Critical infrastructure identification via betweenness centrality" },
      { icon: Target, label: "Segmentation Advice", detail: "Network micro-segmentation recommendations based on exposure" },
    ],
  },
  {
    title: "LLM Orchestration",
    subtitle: "Strategic Reasoning Layer",
    color: "#00f5d4",
    icon: Cpu,
    desc: "Strategies emerge through competition, adaptation, and LLM-powered reasoning.",
    capabilities: [
      { icon: Brain, label: "Strategic Planning", detail: "Multi-step attack/defense chain-of-thought reasoning" },
      { icon: Eye, label: "Incident Analysis", detail: "Alert correlation, root cause analysis, and threat intelligence" },
      { icon: Zap, label: "Tactical Decisions", detail: "Real-time action selection with risk-reward optimization" },
      { icon: Radio, label: "Multi-Model Fallback", detail: "Unified API with GPT-4, Claude, and Gemini fallback chains" },
    ],
  },
];

export default function AgentsPage() {
  return (
    <PageTransition>
      <div className="p-6 md:p-10 max-w-[1400px] mx-auto">
        {/* Header */}
        <div className="mb-12">
          <span className="text-[10px] tracking-[0.3em] uppercase text-[#00f5d4] mb-2 block font-medium">
            System Archetypes
          </span>
          <h1 className="font-serif text-3xl md:text-5xl tracking-wide font-extralight text-white mb-3">
            Evolving Entities
          </h1>
          <p className="text-sm text-white/60 font-light leading-relaxed max-w-2xl">
            Each agent within AMCDS operates as an autonomous entity, learning and adapting through
            competitive co-evolution. Explore the architecture of each system component.
          </p>
        </div>

        {/* Architecture Diagram */}
        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          variants={fadeUpVariants}
          className="glassmorphism-card rounded-2xl p-8 mb-10"
        >
          <h3 className="text-[10px] tracking-[0.3em] uppercase text-white/40 mb-6 font-semibold">
            Multi-Agent Architecture Overview
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-center">
            {["Telemetry\nIngestion", "GNN Risk\nEngine", "LLM\nOrchestration", "RL\nEnvironment", "Defense\nExecution"].map((label, idx) => (
              <div key={idx} className="flex items-center gap-3">
                <div className="flex-1 bg-white/[0.03] border border-white/10 rounded-xl p-4 text-center">
                  <div className="text-[10px] tracking-wider text-white/70 font-mono whitespace-pre-line leading-relaxed">
                    {label}
                  </div>
                </div>
                {idx < 4 && (
                  <div className="hidden md:block text-white/20 text-lg font-light">&rarr;</div>
                )}
              </div>
            ))}
          </div>
        </motion.div>

        {/* Agent Cards */}
        <div className="space-y-8">
          {agents.map((agent, idx) => {
            const Icon = agent.icon;
            return (
              <motion.div
                key={idx}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true, margin: "-50px" }}
                variants={fadeUpVariants}
                className="glassmorphism-card rounded-2xl overflow-hidden"
              >
                <div className="p-8">
                  {/* Agent Header */}
                  <div className="flex items-start justify-between mb-6">
                    <div className="flex items-center gap-4">
                      <div
                        className="w-12 h-12 rounded-xl flex items-center justify-center border"
                        style={{ backgroundColor: `${agent.color}10`, borderColor: `${agent.color}30` }}
                      >
                        <Icon size={20} style={{ color: agent.color }} />
                      </div>
                      <div>
                        <h2 className="text-lg font-light text-white tracking-wider">{agent.title}</h2>
                        <span className="text-[10px] tracking-[0.2em] uppercase font-mono" style={{ color: `${agent.color}99` }}>
                          {agent.subtitle}
                        </span>
                      </div>
                    </div>
                    <span className="text-[10px] tracking-[0.2em] uppercase text-white/20">0{idx + 1}</span>
                  </div>

                  <p className="text-sm text-white/60 font-light leading-relaxed mb-8 max-w-2xl">
                    {agent.desc}
                  </p>

                  {/* Capabilities Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {agent.capabilities.map((cap, cIdx) => {
                      const CapIcon = cap.icon;
                      return (
                        <div
                          key={cIdx}
                          className="bg-white/[0.02] border border-white/5 rounded-xl p-4 group hover:border-white/15 transition-all duration-300"
                        >
                          <div className="flex items-center gap-2 mb-3">
                            <CapIcon size={14} className="text-white/40 group-hover:text-white/70 transition-colors" />
                            <span className="text-[11px] font-semibold tracking-wider uppercase text-white/80">
                              {cap.label}
                            </span>
                          </div>
                          <p className="text-[10px] text-white/40 leading-relaxed font-light group-hover:text-white/55 transition-colors">
                            {cap.detail}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </PageTransition>
  );
}
