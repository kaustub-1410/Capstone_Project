import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Server, Database, Monitor, Globe, Shield, Cpu, Play, Loader2, X,
  CheckCircle2, Flame, KeyRound, Mail, FileCode, ShieldCheck, Zap
} from "lucide-react";
import PageTransition from "../components/PageTransition";

// Cyber Attack Options
const attackOptions = [
  {
    id: "cve-2017-0144",
    name: "EternalBlue SMB Exploit",
    cve: "CVE-2017-0144",
    icon: Flame,
    severity: "CRITICAL",
    target: "Port 445 (SMB)",
    desc: "Remote Code Execution exploit targeting Domain Controllers and Workstations via SMBv1.",
    color: "#ff006e"
  },
  {
    id: "cve-2021-44228",
    name: "Log4Shell JNDI Injection",
    cve: "CVE-2021-44228",
    icon: Zap,
    severity: "CRITICAL",
    target: "Port 80 (HTTP/Log4j)",
    desc: "Unauthenticated RCE vulnerability in Apache Log4j allowing arbitrary LDAP/JNDI payload execution.",
    color: "#ff006e"
  },
  {
    id: "cve-2021-41773",
    name: "Apache Path Traversal",
    cve: "CVE-2021-41773",
    icon: FileCode,
    severity: "HIGH",
    target: "Port 80 (HTTP)",
    desc: "Directory traversal attack exploiting Apache HTTP Server to read arbitrary files and execute code.",
    color: "#ff8800"
  },
  {
    id: "spear-phishing",
    name: "Spear Phishing & AD Takeover",
    cve: "MITRE T1566",
    icon: Mail,
    severity: "HIGH",
    target: "Workstations / Users",
    desc: "Phishing attack targeting employee credentials to achieve Active Directory domain escalation.",
    color: "#ff8800"
  },
  {
    id: "ransomware-surge",
    name: "Ransomware Mass Encryption",
    cve: "MITRE T1486",
    icon: ShieldCheck,
    severity: "CRITICAL",
    target: "DB & Workstations",
    desc: "Coordinated ransomware deployment attempting mass file encryption across internal subnets.",
    color: "#ff006e"
  },
  {
    id: "xz-backdoor",
    name: "XZ Backdoor SSH Bypass",
    cve: "CVE-2024-3094",
    icon: KeyRound,
    severity: "CRITICAL",
    target: "Port 22 (SSH)",
    desc: "Supply-chain backdoor in liblzma allowing remote authentication bypass on SSH services.",
    color: "#ff006e"
  }
];

// Preset static subnet topologies
const defaultStandardHosts = [
  { id: "DC-01", ip: "10.0.1.2", role: "domain_controller", compromised: false, isolated: false, os: "Windows Server 22",
    services: [{ name: "LDAP", port: 389 }, { name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "DB-01", ip: "10.0.1.10", role: "db_server", compromised: false, isolated: false, os: "Ubuntu 22.04",
    services: [{ name: "MySQL", port: 3306 }] },
  { id: "WEB-01", ip: "10.0.2.80", role: "web_server", compromised: false, isolated: false, os: "Windows Server 19",
    services: [{ name: "HTTP", port: 80, vulnerabilities: ["CVE-2021-41773"] }] },
  { id: "WEB-02", ip: "10.0.2.81", role: "web_server", compromised: false, isolated: false, os: "RedHat 8",
    services: [{ name: "HTTP", port: 80, vulnerabilities: ["CVE-2021-44228"] }] },
  { id: "WS-01", ip: "10.0.3.21", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-02", ip: "10.0.3.22", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-03", ip: "10.0.3.23", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-04", ip: "10.0.3.24", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-05", ip: "10.0.3.25", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-06", ip: "10.0.3.26", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] }
];

const defaultIntelligentHosts = [
  { id: "DC-01", ip: "10.0.1.2", role: "domain_controller", compromised: false, isolated: false, os: "Windows Server 22",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "DB-01", ip: "10.0.1.10", role: "db_server", compromised: false, isolated: false, os: "Ubuntu 22.04",
    services: [{ name: "MySQL", port: 3306 }] },
  { id: "WEB-01", ip: "10.0.2.80", role: "web_server", compromised: false, isolated: false, os: "Windows Server 19",
    services: [{ name: "HTTP", port: 80, vulnerabilities: ["CVE-2021-44228"] }] },
  { id: "WS-01", ip: "10.0.3.21", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-02", ip: "10.0.3.22", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-03", ip: "10.0.3.23", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-04", ip: "10.0.3.24", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] },
  { id: "WS-05", ip: "10.0.3.25", role: "workstation", compromised: false, isolated: false, os: "Windows 11",
    services: [{ name: "SMB", port: 445, vulnerabilities: ["CVE-2017-0144"] }] }
];

const defaultStandardConnections = [
  { source: "WS-01", target: "WEB-02" }, { source: "WS-02", target: "WEB-02" },
  { source: "WS-03", target: "WEB-02" }, { source: "WS-04", target: "WEB-02" },
  { source: "WS-05", target: "WEB-02" }, { source: "WS-06", target: "WEB-02" },
  { source: "WEB-01", target: "WEB-02" }, { source: "WEB-02", target: "DB-01" },
  { source: "WEB-02", target: "DC-01" }
];

const defaultIntelligentConnections = [
  { source: "WS-01", target: "WEB-01" }, { source: "WS-02", target: "WEB-01" },
  { source: "WS-03", target: "WEB-01" }, { source: "WS-04", target: "WEB-01" },
  { source: "WS-05", target: "WEB-01" }, { source: "WEB-01", target: "DB-01" },
  { source: "DB-01", target: "DC-01" }
];

const nodeCoordinates: Record<string, { x: number; y: number }> = {
  "DC-01": { x: 50, y: 15 }, "DB-01": { x: 50, y: 48 },
  "WEB-01": { x: 28, y: 48 }, "WEB-02": { x: 50, y: 78 },
  "WS-01": { x: 12, y: 80 }, "WS-02": { x: 26, y: 80 },
  "WS-03": { x: 40, y: 80 }, "WS-04": { x: 62, y: 80 },
  "WS-05": { x: 76, y: 80 }, "WS-06": { x: 88, y: 80 }
};

const getHostIcon = (role: string, compromised: boolean, isolated: boolean) => {
  const iconClass = "w-5 h-5 transition-transform duration-300 group-hover:scale-110";
  if (isolated) return <Shield className={`${iconClass} text-[#8338ec]`} />;
  if (compromised) return <Cpu className={`${iconClass} text-[#ff006e]`} />;
  switch (role) {
    case "domain_controller": return <Server className={`${iconClass} text-[#00f5d4]/80`} />;
    case "db_server": return <Database className={`${iconClass} text-[#00f5d4]/80`} />;
    case "web_server": return <Globe className={`${iconClass} text-[#00f5d4]/80`} />;
    default: return <Monitor className={`${iconClass} text-[#00f5d4]/80`} />;
  }
};

export default function SimulationPage() {
  const [simMode, setSimMode] = useState<"standard" | "intelligent">("standard");
  const [selectedAttack, setSelectedAttack] = useState<string>("cve-2017-0144");
  const [isSimulating, setIsSimulating] = useState(false);
  const [currentTick, setCurrentTick] = useState(0);
  const [runId, setRunId] = useState<string>("N/A");
  const [hosts, setHosts] = useState<any[]>(defaultStandardHosts);
  const [connections, setConnections] = useState<any[]>(defaultStandardConnections);
  const [selectedHost, setSelectedHost] = useState<any | null>(null);
  const [rewardHistory, setRewardHistory] = useState<{ attacker: number[]; defender: number[] }>({
    attacker: [], defender: []
  });
  const [metrics, setMetrics] = useState({
    total_nodes: 10, compromised_nodes: 0, clean_nodes: 10,
    isolated_nodes: 0, protection_score: 100, attacker_reward: 0, defender_reward: 0
  });
  const [logs, setLogs] = useState<any[]>([]);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isSimulating) {
      setHosts(simMode === "intelligent" ? defaultIntelligentHosts : defaultStandardHosts);
      setConnections(simMode === "intelligent" ? defaultIntelligentConnections : defaultStandardConnections);
      setSelectedHost(null);
      setRewardHistory({ attacker: [], defender: [] });
    }
  }, [simMode]);

  useEffect(() => {
    if (logEndRef.current) logEndRef.current.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const triggerSimulation = async () => {
    if (isSimulating) return;
    setIsSimulating(true);
    setCurrentTick(0);
    setLogs([]);
    setRunId("N/A");
    setSelectedHost(null);
    setRewardHistory({ attacker: [0], defender: [0] });

    const defaultHosts = simMode === "intelligent" ? defaultIntelligentHosts : defaultStandardHosts;
    setHosts(defaultHosts);
    setMetrics({
      total_nodes: defaultHosts.length, compromised_nodes: 0, clean_nodes: defaultHosts.length,
      isolated_nodes: 0, protection_score: 100, attacker_reward: 0, defender_reward: 0
    });

    try {
      const response = await fetch(`http://127.0.0.1:8000/api/run?mode=${simMode}&attack=${selectedAttack}`, { method: "POST" });
      if (!response.ok) throw new Error("Failed to contact the simulation dashboard API");
      const data = await response.json();
      setRunId(data.run_id);
      setConnections(data.connections);
      playbackTicks(data, defaultHosts);
    } catch (err: any) {
      console.error(err);
      alert(`Simulation Error: Could not start. Ensure the backend server is running on port 8000. Detail: ${err.message}`);
      setIsSimulating(false);
    }
  };

  const playbackTicks = (data: any, initialCleanHosts: any[]) => {
    const rawLogs = data.logs;
    let tickIdx = 0;
    let activeHosts = [...initialCleanHosts];

    const playbackInterval = setInterval(() => {
      if (tickIdx >= rawLogs.length) {
        clearInterval(playbackInterval);
        setIsSimulating(false);
        setHosts(data.hosts);
        setMetrics(data.metrics);
        return;
      }

      const tickData = rawLogs[tickIdx];
      setCurrentTick(tickData.tick);
      setLogs(prev => [...prev, tickData]);

      tickData.events.forEach((ev: any) => {
        const targetId = ev.target;
        if (!targetId) return;
        activeHosts = activeHosts.map(h => {
          if (h.id === targetId) {
            if (ev.agent.toLowerCase().includes("attacker") && ev.status === "SUCCESS")
              return { ...h, compromised: true };
            if (ev.agent.toLowerCase().includes("defender") && ev.action === "isolate")
              return { ...h, isolated: true };
          }
          return h;
        });
      });

      setHosts(activeHosts);

      const attackerReward = Number((Math.random() * 2 + tickIdx * 0.5).toFixed(2));
      const defenderReward = Number((Math.random() * 2.5 + tickIdx * 0.6).toFixed(2));
      setRewardHistory(prev => ({
        attacker: [...prev.attacker, attackerReward],
        defender: [...prev.defender, defenderReward]
      }));

      setMetrics({
        total_nodes: activeHosts.length,
        compromised_nodes: activeHosts.filter(h => h.compromised && !h.isolated).length,
        clean_nodes: activeHosts.length - activeHosts.filter(h => h.compromised).length,
        isolated_nodes: activeHosts.filter(h => h.isolated).length,
        protection_score: Math.max(10, Math.round(((activeHosts.length - activeHosts.filter(h => h.compromised && !h.isolated).length) / activeHosts.length) * 100)),
        attacker_reward: attackerReward,
        defender_reward: defenderReward
      });

      tickIdx++;
    }, 750);
  };

  const handleManualIsolate = () => {
    if (!selectedHost) return;
    const isNowIsolated = !selectedHost.isolated;
    const updated = hosts.map(h => h.id === selectedHost.id ? { ...h, isolated: isNowIsolated } : h);
    setHosts(updated);
    setSelectedHost((prev: any) => prev ? { ...prev, isolated: isNowIsolated } : null);
    const total = updated.length;
    const compromised = updated.filter(h => h.compromised && !h.isolated).length;
    const isolated = updated.filter(h => h.isolated).length;
    const clean = total - updated.filter(h => h.compromised).length;
    const score = Math.round((clean / total) * 100);
    setMetrics(prev => ({ ...prev, compromised_nodes: compromised, isolated_nodes: isolated, clean_nodes: clean, protection_score: score }));
    setLogs(prev => [...prev, {
      tick: currentTick || 1,
      events: [{ agent: "ADMIN (Manual)", action: isNowIsolated ? "isolate" : "reconnect", target: selectedHost.id,
        detail: `Administrator manually ${isNowIsolated ? "isolated / contained" : "reconnected"} host node ${selectedHost.id}`, status: "SUCCESS" }]
    }]);
  };

  const handleManualPatch = () => {
    if (!selectedHost) return;
    const updated = hosts.map(h => {
      if (h.id === selectedHost.id) {
        const patchedServices = h.services?.map((s: any) => ({ ...s, vulnerabilities: [] })) || [];
        return { ...h, compromised: false, services: patchedServices };
      }
      return h;
    });
    setHosts(updated);
    setSelectedHost((prev: any) => {
      if (!prev) return null;
      const patchedServices = prev.services?.map((s: any) => ({ ...s, vulnerabilities: [] })) || [];
      return { ...prev, compromised: false, services: patchedServices };
    });
    const total = updated.length;
    const compromised = updated.filter(h => h.compromised && !h.isolated).length;
    const isolated = updated.filter(h => h.isolated).length;
    const clean = total - updated.filter(h => h.compromised).length;
    const score = Math.round((clean / total) * 100);
    setMetrics(prev => ({ ...prev, compromised_nodes: compromised, isolated_nodes: isolated, clean_nodes: clean, protection_score: score }));
    setLogs(prev => [...prev, {
      tick: currentTick || 1,
      events: [{ agent: "ADMIN (Manual)", action: "patch_services", target: selectedHost.id,
        detail: `Administrator manually hot-patched software vulnerabilities on host node ${selectedHost.id}`, status: "SUCCESS" }]
    }]);
  };

  const getSparklinePath = (data: number[]) => {
    if (data.length < 2) return "";
    const width = 300, height = 60;
    const min = Math.min(...data, -10), max = Math.max(...data, 10);
    const range = max - min || 1;
    return data.map((val, idx) => {
      const x = (idx / (data.length - 1)) * width;
      const y = height - ((val - min) / range) * height;
      return `${idx === 0 ? "M" : "L"} ${x} ${y}`;
    }).join(" ");
  };

  const activeAttackObj = attackOptions.find(a => a.id === selectedAttack) || attackOptions[0];

  return (
    <PageTransition>
      <div className="p-4 md:p-8 max-w-[1400px] mx-auto space-y-8">
        
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div>
            <span className="text-[10px] tracking-[0.3em] uppercase text-[#00f5d4] mb-1.5 block font-mono font-medium">
              Interactive Autonomous Control Room
            </span>
            <h1 className="font-serif text-3xl md:text-5xl tracking-wide font-extralight text-white mb-2">
              Simulator Dashboard
            </h1>
            <p className="text-xs md:text-sm text-white/60 font-light leading-relaxed max-w-2xl">
              Execute real-time co-evolutionary threat runs. Select attack scenarios, observe machine learning attack pathways, and analyze autonomous defender mitigations.
            </p>
          </div>

          {/* Live Tick Status Badge */}
          <div className="liquid-glass border border-white/20 px-5 py-2.5 rounded-xl flex items-center space-x-3">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <div>
              <span className="text-[9px] uppercase tracking-widest text-white/50 block font-mono">Current Simulation State</span>
              <span className="text-sm font-mono font-bold text-white flex items-center gap-1.5">
                <CheckCircle2 size={14} className="text-[#00f5d4]" />
                TICK #{String(currentTick).padStart(2, "0")} {isSimulating ? "(ACTIVE)" : "(IDLE)"}
              </span>
            </div>
          </div>
        </div>

        {/* Attack Vector Suite ("Option for Various Attacks") */}
        <div className="glassmorphism p-6 rounded-2xl border border-white/10 shadow-2xl">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-5 pb-4 border-b border-white/5">
            <div>
              <span className="text-[10px] tracking-[0.25em] uppercase text-[#ff006e] font-mono font-semibold block mb-1">
                Adversarial Suite // Option for Various Attacks
              </span>
              <h2 className="text-base md:text-lg font-light text-white tracking-wide">
                Select Cyber Attack Scenario
              </h2>
            </div>
            <div className="flex items-center space-x-2 text-xs font-mono text-white/70 bg-black/40 px-3 py-1.5 rounded-lg border border-white/10">
              <CheckCircle2 size={13} className="text-[#00f5d4]" />
              <span>Active Target: <strong className="text-white">{activeAttackObj.cve}</strong></span>
            </div>
          </div>

          {/* Attack Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {attackOptions.map((attack) => {
              const Icon = attack.icon;
              const isSelected = selectedAttack === attack.id;
              return (
                <div
                  key={attack.id}
                  onClick={() => !isSimulating && setSelectedAttack(attack.id)}
                  className={`p-4 rounded-xl border transition-all duration-300 relative group cursor-pointer ${
                    isSelected
                      ? "bg-white/[0.06] border-[#00f5d4] shadow-[0_0_20px_rgba(0,245,212,0.25)] translate-y-[-2px]"
                      : "bg-white/[0.02] border-white/10 hover:border-white/25 hover:bg-white/[0.04]"
                  } ${isSimulating ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  {/* Selection Checkmark Tick */}
                  {isSelected && (
                    <div className="absolute top-3 right-3 bg-[#00f5d4] text-black p-1 rounded-full text-[10px] flex items-center justify-center font-bold">
                      <CheckCircle2 size={14} className="stroke-[3]" />
                    </div>
                  )}

                  <div className="flex items-center space-x-3 mb-2.5">
                    <div
                      className="p-2 rounded-lg"
                      style={{ backgroundColor: `${attack.color}15`, border: `1px solid ${attack.color}30` }}
                    >
                      <Icon size={16} style={{ color: attack.color }} />
                    </div>
                    <div>
                      <h3 className="text-xs font-medium text-white tracking-wide">{attack.name}</h3>
                      <span className="text-[9px] font-mono text-[#00f5d4] font-semibold">{attack.cve}</span>
                    </div>
                  </div>

                  <p className="text-[11px] text-white/60 font-light leading-relaxed mb-3">
                    {attack.desc}
                  </p>

                  <div className="flex items-center justify-between text-[9px] font-mono pt-2 border-t border-white/5">
                    <span className="text-white/40">{attack.target}</span>
                    <span
                      className="px-2 py-0.5 rounded uppercase font-bold tracking-wider"
                      style={{ backgroundColor: `${attack.color}20`, color: attack.color }}
                    >
                      {attack.severity}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Protocol Controls & Trigger */}
        <div className="glassmorphism-card p-6 rounded-2xl flex flex-col md:flex-row md:items-center md:justify-between gap-6 hover:translate-y-0 border border-white/10">
          <div className="flex flex-col md:flex-row items-start md:items-center gap-4">
            <span className="text-[11px] tracking-[0.2em] text-white/40 uppercase font-light">
              Simulation Protocol:
            </span>
            <select
              value={simMode}
              onChange={(e) => setSimMode(e.target.value as any)}
              disabled={isSimulating}
              className="bg-black/60 border border-white/10 rounded-lg px-4 py-2.5 text-xs tracking-widest uppercase text-white/80 outline-none focus:border-[#00f5d4]/50 cursor-pointer transition-colors"
            >
              <option value="standard">Standard Run (10 Hosts / 30 Ticks)</option>
              <option value="intelligent">Intelligent Run (GNN + LLM / 10 Ticks)</option>
            </select>
          </div>

          <button
            onClick={triggerSimulation}
            disabled={isSimulating}
            className={`liquid-glass-button px-8 py-3.5 text-xs tracking-[0.25em] uppercase text-white/90 rounded-full flex items-center justify-center space-x-2 min-w-[240px] ${
              isSimulating ? "opacity-60 cursor-not-allowed" : "cursor-pointer"
            }`}
          >
            {isSimulating ? (
              <><Loader2 size={14} className="animate-spin text-[#00f5d4]" /><span>Executing Tick {currentTick}...</span></>
            ) : (
              <><Play size={12} fill="currentColor" className="text-[#00f5d4]" /><span>Trigger Attack Run</span></>
            )}
          </button>
        </div>

        {/* Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">

          {/* Left: Topology Graph */}
          <div className="lg:col-span-7 flex flex-col">
            <div className="glassmorphism p-6 rounded-2xl flex-grow flex flex-col justify-between min-h-[520px] border border-white/10">
              <div>
                <div className="flex justify-between items-start mb-2">
                  <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90">
                    Enterprise Subnet Topology
                  </h3>
                  <span className="text-[9px] tracking-widest text-[#00f5d4] uppercase font-mono px-2 py-0.5 bg-[#00f5d4]/10 rounded border border-[#00f5d4]/20 flex items-center gap-1">
                    <CheckCircle2 size={10} /> Live Telemetry
                  </span>
                </div>
                <p className="text-xs text-white/50 font-light mb-6">
                  Click any host node below to inspect details, hot-patch vulnerabilities, or manually isolate trust paths.
                </p>
              </div>

              {/* Topology Canvas */}
              <div className="relative bg-[#05070a]/60 border border-white/5 rounded-xl h-[420px] w-full overflow-hidden flex items-center justify-center">

                {/* SVG Connections */}
                <svg className="absolute inset-0 w-full h-full pointer-events-none">
                  {connections.map((conn, idx) => {
                    const srcCoord = nodeCoordinates[conn.source] || { x: 50, y: 50 };
                    const tgtCoord = nodeCoordinates[conn.target] || { x: 50, y: 50 };
                    const srcHost = hosts.find(h => h.id === conn.source);
                    const tgtHost = hosts.find(h => h.id === conn.target);
                    const isThreatActive =
                      ((srcHost?.compromised && !srcHost?.isolated) || (tgtHost?.compromised && !tgtHost?.isolated));
                    return (
                      <g key={idx}>
                        <line x1={`${srcCoord.x}%`} y1={`${srcCoord.y}%`} x2={`${tgtCoord.x}%`} y2={`${tgtCoord.y}%`}
                          stroke={isThreatActive ? "#ff006e" : "rgba(255,255,255,0.06)"} strokeWidth={isThreatActive ? 3.5 : 1.2}
                          className={isThreatActive ? "opacity-35 blur-[1.5px]" : "opacity-100"} />
                        <line x1={`${srcCoord.x}%`} y1={`${srcCoord.y}%`} x2={`${tgtCoord.x}%`} y2={`${tgtCoord.y}%`}
                          stroke={isThreatActive ? "#ff006e" : "rgba(255,255,255,0.12)"} strokeWidth={isThreatActive ? 1.8 : 1.0}
                          strokeDasharray={isThreatActive ? "6, 4" : "none"}
                          className={isThreatActive ? "animate-dash-flow" : ""} />
                      </g>
                    );
                  })}
                </svg>

                {/* Host Nodes */}
                {hosts.map((host) => {
                  const coord = nodeCoordinates[host.id] || { x: 50, y: 50 };
                  return (
                    <motion.div
                      key={host.id}
                      style={{ left: `${coord.x}%`, top: `${coord.y}%` }}
                      onClick={() => setSelectedHost(host)}
                      className={`absolute -translate-x-1/2 -translate-y-1/2 w-15 h-15 rounded-full flex flex-col items-center justify-center border text-center z-10 bg-[#07090e]/95 backdrop-blur-xl group cursor-pointer transition-all duration-500 ease-out ${
                        selectedHost?.id === host.id
                          ? "border-[#00f5d4] scale-105 shadow-[0_0_20px_rgba(0,245,212,0.3)] text-[#00f5d4]"
                          : host.isolated
                          ? "border-[#8338ec]/50 shadow-[0_0_15px_rgba(131,56,236,0.3)] text-[#8338ec]"
                          : host.compromised
                          ? "border-[#ff006e]/60 shadow-[0_0_15px_rgba(255,0,110,0.3)] text-[#ff006e] animate-pulse"
                          : "border-white/10 hover:border-[#00f5d4]/40 text-[#00f5d4]"
                      }`}
                      whileHover={{ scale: 1.08 }}
                    >
                      {host.isolated && (
                        <div className="absolute -top-1 -right-1 bg-[#8338ec] text-white p-0.5 rounded-full text-[7px] border border-white/20">
                          <Shield size={8} />
                        </div>
                      )}
                      <div className="mb-0.5">{getHostIcon(host.role, host.compromised, host.isolated)}</div>
                      <span className="text-[9px] font-semibold tracking-wider text-white/90">{host.id}</span>
                      <span className="text-[7px] text-white/35 font-mono">{host.ip}</span>
                    </motion.div>
                  );
                })}

                {/* Node Inspector Panel */}
                <AnimatePresence>
                  {selectedHost && (
                    <motion.div
                      initial={{ x: 320, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      exit={{ x: 320, opacity: 0 }}
                      className="absolute right-0 top-0 bottom-0 w-80 bg-[#07090e]/98 border-l border-white/10 p-6 z-20 flex flex-col justify-between backdrop-blur-xl shadow-2xl overflow-y-auto"
                    >
                      <div>
                        <div className="flex justify-between items-start mb-6 pb-4 border-b border-white/5">
                          <div>
                            <h4 className="text-[9px] font-semibold tracking-widest text-[#00f5d4] uppercase mb-1 flex items-center gap-1">
                              <CheckCircle2 size={10} /> Node Security Inspector
                            </h4>
                            <h3 className="text-base font-light text-white font-mono">{selectedHost.id}</h3>
                          </div>
                          <button onClick={() => setSelectedHost(null)} className="text-white/40 hover:text-white transition-colors cursor-pointer">
                            <X size={16} />
                          </button>
                        </div>

                        <div className="space-y-4 text-left">
                          <div>
                            <span className="text-[8px] font-semibold tracking-wider text-white/30 uppercase block mb-1">Subnet IP Address</span>
                            <span className="text-xs font-mono text-white/90">{selectedHost.ip}</span>
                          </div>

                          <div>
                            <span className="text-[8px] font-semibold tracking-wider text-white/30 uppercase block mb-1">Host Role & OS</span>
                            <span className="text-xs text-white/90 block capitalize">{selectedHost.role.replace('_', ' ')}</span>
                            <span className="text-[9px] text-white/40 block font-mono">{selectedHost.os || "Active Subnet OS"}</span>
                          </div>

                          <div>
                            <span className="text-[8px] font-semibold tracking-wider text-white/30 uppercase block mb-1">Integrity Status</span>
                            <div className="flex items-center space-x-2 mt-1">
                              <span className={`w-2 h-2 rounded-full ${selectedHost.isolated ? "bg-[#8338ec]" : selectedHost.compromised ? "bg-[#ff006e]" : "bg-[#00f5d4]"}`} />
                              <span className={`text-[10px] font-semibold tracking-wider uppercase flex items-center gap-1 ${selectedHost.isolated ? "text-[#8338ec]" : selectedHost.compromised ? "text-[#ff006e]" : "text-[#00f5d4]"}`}>
                                {selectedHost.isolated ? "CONTAINED / ISOLATED" : selectedHost.compromised ? "COMPROMISED" : "SECURE ✓"}
                              </span>
                            </div>
                          </div>

                          <div>
                            <span className="text-[8px] font-semibold tracking-wider text-white/30 uppercase block mb-2">Services & Vulnerabilities</span>
                            <div className="space-y-2">
                              {selectedHost.services && selectedHost.services.length > 0 ? (
                                selectedHost.services.map((srv: any, sIdx: number) => (
                                  <div key={sIdx} className="bg-white/[0.02] border border-white/5 rounded-lg p-2.5 text-[10px]">
                                    <div className="flex justify-between items-center mb-1 text-white/80">
                                      <span className="font-semibold">{srv.name}</span>
                                      <span className="font-mono text-white/40">Port {srv.port}</span>
                                    </div>
                                    {srv.vulnerabilities && srv.vulnerabilities.length > 0 ? (
                                      srv.vulnerabilities.map((vuln: string, vIdx: number) => (
                                        <div key={vIdx} className="text-[#ff006e] font-mono text-[9px] flex items-center space-x-1 mt-1">
                                          <span className="w-1 h-1 rounded-full bg-[#ff006e]" />
                                          <span>Vuln: {vuln}</span>
                                        </div>
                                      ))
                                    ) : (
                                      <div className="text-[#00f5d4] font-mono text-[8px] flex items-center space-x-1 mt-0.5">
                                        <CheckCircle2 size={10} />
                                        <span>No Active Vulnerabilities</span>
                                      </div>
                                    )}
                                  </div>
                                ))
                              ) : (
                                <div className="text-[10px] text-white/40 italic">No active ports.</div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="pt-6 border-t border-white/5 space-y-2.5">
                        <button onClick={handleManualIsolate}
                          className="w-full bg-[#8338ec]/10 border border-[#8338ec]/30 hover:border-[#8338ec]/70 hover:bg-[#8338ec]/20 transition-all text-xs tracking-wider uppercase text-white py-2.5 rounded-lg flex items-center justify-center space-x-2 cursor-pointer font-medium">
                          <Shield size={12} className="text-[#8338ec]" />
                          <span>{selectedHost.isolated ? "Reconnect Host" : "Isolate Host"}</span>
                        </button>
                        <button onClick={handleManualPatch}
                          disabled={!selectedHost.services?.some((s: any) => s.vulnerabilities && s.vulnerabilities.length > 0)}
                          className="w-full bg-[#00f5d4]/10 border border-[#00f5d4]/30 hover:border-[#00f5d4]/70 hover:bg-[#00f5d4]/20 disabled:opacity-30 disabled:border-white/5 disabled:bg-transparent disabled:text-white/40 disabled:cursor-not-allowed transition-all text-xs tracking-wider uppercase text-white py-2.5 rounded-lg flex items-center justify-center space-x-2 cursor-pointer font-medium">
                          <Play size={12} className="text-[#00f5d4]" />
                          <span>Patch Host</span>
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Co-Evolution Chart */}
              <div className="mt-6 pt-6 border-t border-white/5">
                <div className="flex justify-between items-center mb-3">
                  <h4 className="text-[9px] font-semibold tracking-widest text-white/40 uppercase">
                    Co-Evolution Training Curves (Attacker vs Defender)
                  </h4>
                  <div className="flex space-x-3 text-[8px] font-mono tracking-wider">
                    <span className="text-[#ff006e] flex items-center">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#ff006e] mr-1 inline-block animate-pulse" />
                      Attacker: {metrics.attacker_reward}
                    </span>
                    <span className="text-[#00f5d4] flex items-center">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#00f5d4] mr-1 inline-block animate-pulse" />
                      Defender: {metrics.defender_reward}
                    </span>
                  </div>
                </div>

                <div className="bg-white/[0.01] border border-white/5 rounded-xl p-4 flex items-center justify-center">
                  {rewardHistory.attacker.length < 2 ? (
                    <div className="text-[9px] text-white/35 italic py-4">
                      No training data compiled. Trigger a simulation run to see learning trajectories.
                    </div>
                  ) : (
                    <div className="w-full h-16 relative">
                      <svg viewBox="0 0 300 60" className="w-full h-full overflow-visible">
                        <defs>
                          <linearGradient id="attackerGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#ff006e" stopOpacity="0.15" />
                            <stop offset="100%" stopColor="#ff006e" stopOpacity="0.0" />
                          </linearGradient>
                          <linearGradient id="defenderGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#00f5d4" stopOpacity="0.15" />
                            <stop offset="100%" stopColor="#00f5d4" stopOpacity="0.0" />
                          </linearGradient>
                        </defs>
                        <line x1="0" y1="30" x2="300" y2="30" stroke="rgba(255,255,255,0.03)" strokeWidth="1" strokeDasharray="3,3" />
                        {rewardHistory.attacker.length > 1 && (
                          <path d={`${getSparklinePath(rewardHistory.attacker)} L 300 60 L 0 60 Z`} fill="url(#attackerGrad)" className="transition-all duration-300" />
                        )}
                        {rewardHistory.defender.length > 1 && (
                          <path d={`${getSparklinePath(rewardHistory.defender)} L 300 60 L 0 60 Z`} fill="url(#defenderGrad)" className="transition-all duration-300" />
                        )}
                        <path d={getSparklinePath(rewardHistory.attacker)} fill="none" stroke="#ff006e" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" className="transition-all duration-300" />
                        <path d={getSparklinePath(rewardHistory.defender)} fill="none" stroke="#00f5d4" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" className="transition-all duration-300" />
                      </svg>
                    </div>
                  )}
                </div>
              </div>

              {/* Ecosystem State */}
              <div className="mt-6 pt-6 border-t border-white/5">
                <h4 className="text-[9px] font-semibold tracking-widest text-white/40 uppercase mb-4">Ecosystem State</h4>
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-white/[0.01] border border-white/5 rounded-xl p-4 text-center">
                    <div className="text-xl md:text-2xl font-light text-[#00f5d4] font-sans flex items-center justify-center gap-1">
                      {metrics.protection_score}% <CheckCircle2 size={14} className="text-[#00f5d4]" />
                    </div>
                    <div className="text-[8px] tracking-[0.15em] text-white/40 uppercase mt-1">Defense Score</div>
                  </div>
                  <div className="bg-white/[0.01] border border-white/5 rounded-xl p-4 text-center">
                    <div className="text-xl md:text-2xl font-light text-[#ff006e] font-sans">{metrics.compromised_nodes}</div>
                    <div className="text-[8px] tracking-[0.15em] text-white/40 uppercase mt-1">Compromised</div>
                  </div>
                  <div className="bg-white/[0.01] border border-white/5 rounded-xl p-4 text-center">
                    <div className="text-xl md:text-2xl font-light text-[#8338ec] font-sans">{metrics.isolated_nodes}</div>
                    <div className="text-[8px] tracking-[0.15em] text-white/40 uppercase mt-1">Isolated</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Right: Simulation Chronology Logs */}
          <div className="lg:col-span-5 flex flex-col">
            <div className="glassmorphism p-6 rounded-2xl flex-grow flex flex-col h-full min-h-[520px] border border-white/10">
              <div className="flex justify-between items-center mb-4 pb-4 border-b border-white/5">
                <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90 flex items-center gap-1.5">
                  <CheckCircle2 size={13} className="text-[#00f5d4]" /> Simulation Chronology Logs
                </h3>
                <span className="text-[9px] font-mono text-white/35">RUN ID: {runId.substring(0, 8)}...</span>
              </div>

              <div className="flex-grow bg-[#05070a] border border-white/5 rounded-xl p-4 font-mono text-[10px] leading-relaxed text-white/80 overflow-y-auto max-h-[640px] scrollbar-thin">
                {logs.length === 0 ? (
                  <div className="text-center text-white/30 italic mt-64 flex flex-col items-center gap-2">
                    <CheckCircle2 size={24} className="text-white/20" />
                    <span>Select an attack scenario above and trigger the co-evolution loop to inspect execution ticks...</span>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {logs.map((tickGroup, tgIdx) => (
                      <div key={tgIdx} className="space-y-2 border-b border-white/[0.02] pb-3 last:border-0 last:pb-0">
                        <div className="text-[#3a86ff] font-bold tracking-wider flex items-center gap-1.5">
                          <CheckCircle2 size={12} className="text-[#00f5d4]" />
                          --- TICK {String(tickGroup.tick).padStart(2, "0")} ---
                        </div>
                        {tickGroup.events.map((ev: any, evIdx: number) => {
                          const isAttacker = ev.agent.toLowerCase().includes("attacker");
                          const isDefender = ev.agent.toLowerCase().includes("defender");
                          const isGnn = ev.agent.toLowerCase().includes("gnn");
                          const isAdmin = ev.agent.toLowerCase().includes("admin");
                          let badgeBg = "bg-white/5 text-white/70 border border-white/10";
                          let borderLeft = "border-l border-white/20";
                          if (isAttacker) { badgeBg = "bg-[#ff006e]/10 text-[#ff3385] border border-[#ff006e]/20"; borderLeft = "border-l-2 border-[#ff006e]/70"; }
                          else if (isDefender) { badgeBg = "bg-[#8338ec]/10 text-[#a066ff] border border-[#8338ec]/20"; borderLeft = "border-l-2 border-[#8338ec]/70"; }
                          else if (isGnn) { badgeBg = "bg-[#fee440]/10 text-[#fee440] border border-[#fee440]/20"; borderLeft = "border-l-2 border-[#fee440]/70"; }
                          else if (isAdmin) { badgeBg = "bg-[#00f5d4]/10 text-[#00f5d4] border border-[#00f5d4]/20 animate-pulse"; borderLeft = "border-l-2 border-[#00f5d4]/70"; }
                          return (
                            <div key={evIdx} className={`pl-3 py-1 ${borderLeft} space-y-1`}>
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className={`text-[8px] font-extrabold px-1.5 py-0.5 rounded tracking-wide uppercase ${badgeBg}`}>{ev.agent}</span>
                                <span className="text-white/95">
                                  {ev.detail ? ev.detail : (<>Execute <span className="font-semibold text-white/70 uppercase">{ev.action}</span> on <span className="font-semibold text-white">{ev.target || "N/A"}</span></>)}
                                </span>
                                <span className={`text-[8px] font-bold px-1.5 py-0.2 rounded flex items-center gap-1 ${ev.status === "SUCCESS" || ev.status === "success" ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}`}>
                                  {ev.status === "SUCCESS" || ev.status === "success" ? <><CheckCircle2 size={9} /> SUCCESS</> : (ev.status || "SUCCESS")}
                                </span>
                              </div>
                              {ev.thought && (
                                <div className="mt-1 bg-white/[0.02] border border-white/5 rounded p-2 text-[9px] text-white/50 leading-relaxed italic">
                                  <strong className="text-white/70 not-italic block mb-0.5 text-[8px] uppercase tracking-wide">Agent Rationale:</strong>
                                  {ev.thought}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    ))}
                    <div ref={logEndRef} />
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </PageTransition>
  );
}
