import { useState } from "react";
import { motion } from "framer-motion";
import { BarChart3, TrendingUp, AlertTriangle, Shield, Activity, Loader2 } from "lucide-react";
import PageTransition from "../components/PageTransition";

const fadeUpVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 1.0, ease: [0.16, 1, 0.3, 1] as any } },
};

interface RunRecord {
  id: string;
  mode: string;
  timestamp: string;
  protection_score: number;
  compromised: number;
  isolated: number;
  total: number;
  attacker_reward: number;
  defender_reward: number;
}

const cveDatabase = [
  { id: "CVE-2017-0144", name: "EternalBlue", severity: "CRITICAL", cvss: 9.8, affected: "SMB (Port 445)", color: "#ff006e" },
  { id: "CVE-2021-44228", name: "Log4Shell", severity: "CRITICAL", cvss: 10.0, affected: "HTTP (Port 80)", color: "#ff006e" },
  { id: "CVE-2021-41773", name: "Apache Path Traversal", severity: "HIGH", cvss: 7.5, affected: "HTTP (Port 80)", color: "#ff8800" },
  { id: "CVE-2023-44487", name: "HTTP/2 Rapid Reset", severity: "HIGH", cvss: 7.5, affected: "HTTP/2 Services", color: "#ff8800" },
  { id: "CVE-2024-3094", name: "XZ Backdoor", severity: "CRITICAL", cvss: 10.0, affected: "SSH (Port 22)", color: "#ff006e" },
  { id: "CVE-2023-4863", name: "libwebp Heap Overflow", severity: "HIGH", cvss: 8.8, affected: "Web Browsers", color: "#ff8800" },
];

const riskNodes = [
  { id: "DC-01", role: "Domain Controller", riskScore: 0.94, criticalPaths: 4, vulns: 1 },
  { id: "WEB-02", role: "Web Server", riskScore: 0.87, criticalPaths: 7, vulns: 1 },
  { id: "DB-01", role: "Database Server", riskScore: 0.72, criticalPaths: 2, vulns: 0 },
  { id: "WEB-01", role: "Web Server", riskScore: 0.68, criticalPaths: 1, vulns: 1 },
  { id: "WS-01", role: "Workstation", riskScore: 0.55, criticalPaths: 1, vulns: 1 },
  { id: "WS-02", role: "Workstation", riskScore: 0.52, criticalPaths: 1, vulns: 1 },
  { id: "WS-03", role: "Workstation", riskScore: 0.49, criticalPaths: 1, vulns: 1 },
];

export default function AnalyticsPage() {
  const [runHistory, setRunHistory] = useState<RunRecord[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const runQuickAnalysis = async () => {
    setIsLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:8000/api/run?mode=standard", { method: "POST" });
      if (response.ok) {
        const data = await response.json();
        const record: RunRecord = {
          id: data.run_id.substring(0, 8),
          mode: "Standard",
          timestamp: new Date().toLocaleTimeString(),
          protection_score: data.metrics.protection_score,
          compromised: data.metrics.compromised_nodes,
          isolated: data.metrics.isolated_nodes,
          total: data.metrics.total_nodes,
          attacker_reward: data.metrics.attacker_reward,
          defender_reward: data.metrics.defender_reward,
        };
        setRunHistory(prev => [record, ...prev].slice(0, 10));
      }
    } catch (err) {
      console.error("Analysis run failed:", err);
    }
    setIsLoading(false);
  };

  return (
    <PageTransition>
      <div className="p-6 md:p-10 max-w-[1400px] mx-auto">
        {/* Header */}
        <div className="mb-10 flex flex-col md:flex-row md:items-end md:justify-between gap-4">
          <div>
            <span className="text-[10px] tracking-[0.3em] uppercase text-[#00f5d4] mb-2 block font-medium">
              Intelligence Reports
            </span>
            <h1 className="font-serif text-3xl md:text-5xl tracking-wide font-extralight text-white mb-3">
              Analytics & Reports
            </h1>
            <p className="text-sm text-white/60 font-light leading-relaxed max-w-2xl">
              Post-simulation analytics, CVE intelligence, GNN risk rankings, and historical run comparisons.
            </p>
          </div>
          <button
            onClick={runQuickAnalysis}
            disabled={isLoading}
            className={`liquid-glass-button px-6 py-3 text-xs tracking-[0.2em] uppercase text-white/90 rounded-full flex items-center space-x-2 ${
              isLoading ? "opacity-60 cursor-not-allowed" : "cursor-pointer"
            }`}
          >
            {isLoading ? (
              <><Loader2 size={14} className="animate-spin text-[#00f5d4]" /><span>Running...</span></>
            ) : (
              <><Activity size={14} className="text-[#00f5d4]" /><span>Quick Analysis Run</span></>
            )}
          </button>
        </div>

        {/* Stats Overview */}
        <motion.div
          initial="hidden" whileInView="visible" viewport={{ once: true }}
          variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.08 } } }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10"
        >
          {[
            { value: "6", label: "Known CVEs", icon: AlertTriangle, color: "#ff006e" },
            { value: "7", label: "Nodes Monitored", icon: Activity, color: "#00f5d4" },
            { value: runHistory.length.toString(), label: "Analysis Runs", icon: BarChart3, color: "#3a86ff" },
            { value: runHistory.length > 0 ? `${runHistory[0].protection_score}%` : "--", label: "Latest Defense", icon: Shield, color: "#8338ec" },
          ].map((stat, idx) => {
            const Icon = stat.icon;
            return (
              <motion.div key={idx} variants={fadeUpVariants} className="glassmorphism-card rounded-2xl p-6 text-center">
                <Icon size={18} className="mx-auto mb-3 opacity-60" style={{ color: stat.color }} />
                <div className="text-2xl font-light font-sans text-white mb-1">{stat.value}</div>
                <div className="text-[9px] tracking-[0.15em] text-white/40 uppercase">{stat.label}</div>
              </motion.div>
            );
          })}
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-10">
          {/* CVE Intelligence */}
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
            <div className="glassmorphism-card rounded-2xl p-6 h-full">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90">CVE Intelligence Database</h3>
                <AlertTriangle size={14} className="text-[#ff006e]/60" />
              </div>
              <div className="space-y-3">
                {cveDatabase.map((cve, idx) => (
                  <div key={idx} className="bg-white/[0.02] border border-white/5 rounded-xl p-4 hover:border-white/10 transition-all group">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <span className="text-xs font-mono text-white/90 font-semibold">{cve.id}</span>
                        <span className="text-[10px] text-white/50 ml-2">{cve.name}</span>
                      </div>
                      <span className="text-[8px] font-bold px-2 py-0.5 rounded tracking-wider uppercase" style={{ backgroundColor: `${cve.color}15`, color: cve.color, border: `1px solid ${cve.color}30` }}>
                        {cve.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-[9px] text-white/40">
                      <span>CVSS: <strong className="text-white/70">{cve.cvss}</strong></span>
                      <span>Affects: <strong className="text-white/60">{cve.affected}</strong></span>
                    </div>
                    {/* CVSS Bar */}
                    <div className="mt-2 h-1 bg-white/5 rounded-full overflow-hidden">
                      <div className="h-full rounded-full transition-all duration-500 group-hover:opacity-100 opacity-70" style={{ width: `${cve.cvss * 10}%`, backgroundColor: cve.color }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>

          {/* GNN Risk Rankings */}
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
            <div className="glassmorphism-card rounded-2xl p-6 h-full">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90">GNN Risk Score Rankings</h3>
                <TrendingUp size={14} className="text-[#00f5d4]/60" />
              </div>
              <div className="space-y-3">
                {riskNodes.map((node, idx) => (
                  <div key={idx} className="bg-white/[0.02] border border-white/5 rounded-xl p-4 hover:border-white/10 transition-all group">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <span className="text-[10px] text-white/25 font-mono w-4">#{idx + 1}</span>
                        <div>
                          <span className="text-xs font-mono text-white/90 font-semibold">{node.id}</span>
                          <span className="text-[10px] text-white/40 ml-2">{node.role}</span>
                        </div>
                      </div>
                      <span className={`text-sm font-mono font-semibold ${node.riskScore > 0.8 ? "text-[#ff006e]" : node.riskScore > 0.6 ? "text-[#ff8800]" : "text-[#00f5d4]"}`}>
                        {node.riskScore.toFixed(2)}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-[9px] text-white/40 mb-2">
                      <span>Critical Paths: <strong className="text-white/60">{node.criticalPaths}</strong></span>
                      <span>Active CVEs: <strong className={node.vulns > 0 ? "text-[#ff006e]" : "text-[#00f5d4]"}>{node.vulns}</strong></span>
                    </div>
                    <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-700 group-hover:opacity-100 opacity-80"
                        style={{
                          width: `${node.riskScore * 100}%`,
                          background: node.riskScore > 0.8 ? "linear-gradient(90deg, #ff006e, #ff3385)" : node.riskScore > 0.6 ? "linear-gradient(90deg, #ff8800, #ffaa44)" : "linear-gradient(90deg, #00f5d4, #00d4aa)"
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </div>

        {/* Run History Table */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
          <div className="glassmorphism-card rounded-2xl p-6">
            <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90 mb-6">Simulation Run History</h3>
            {runHistory.length === 0 ? (
              <div className="text-center py-16 text-white/30 text-xs italic">
                No analysis runs recorded yet. Click "Quick Analysis Run" above to generate data.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-[11px] font-mono">
                  <thead>
                    <tr className="border-b border-white/10 text-white/40 text-left">
                      <th className="py-3 px-2 tracking-wider uppercase">Run ID</th>
                      <th className="py-3 px-2 tracking-wider uppercase">Mode</th>
                      <th className="py-3 px-2 tracking-wider uppercase">Time</th>
                      <th className="py-3 px-2 tracking-wider uppercase">Defense</th>
                      <th className="py-3 px-2 tracking-wider uppercase">Compromised</th>
                      <th className="py-3 px-2 tracking-wider uppercase">Isolated</th>
                      <th className="py-3 px-2 tracking-wider uppercase">Attacker Rwd</th>
                      <th className="py-3 px-2 tracking-wider uppercase">Defender Rwd</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runHistory.map((run, idx) => (
                      <tr key={idx} className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                        <td className="py-3 px-2 text-white/80">{run.id}...</td>
                        <td className="py-3 px-2 text-white/60">{run.mode}</td>
                        <td className="py-3 px-2 text-white/50">{run.timestamp}</td>
                        <td className="py-3 px-2">
                          <span className={`font-semibold ${run.protection_score >= 70 ? "text-[#00f5d4]" : run.protection_score >= 40 ? "text-[#ff8800]" : "text-[#ff006e]"}`}>
                            {run.protection_score}%
                          </span>
                        </td>
                        <td className="py-3 px-2 text-[#ff006e]">{run.compromised}/{run.total}</td>
                        <td className="py-3 px-2 text-[#8338ec]">{run.isolated}</td>
                        <td className="py-3 px-2 text-[#ff006e]">{run.attacker_reward}</td>
                        <td className="py-3 px-2 text-[#00f5d4]">{run.defender_reward}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </PageTransition>
  );
}
