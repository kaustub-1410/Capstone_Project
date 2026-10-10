import { motion } from "framer-motion";
import type { Variants } from "framer-motion";
import { Shield, GitBranch, Mail, ExternalLink } from "lucide-react";
import PageTransition from "../components/PageTransition";

const fadeUpVariants: Variants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 1.0, ease: [0.16, 1, 0.3, 1] as any } },
};

const stats = [
  { value: "1000+", label: "Simulated Assets" },
  { value: "50+", label: "Intelligent Agents" },
  { value: "24/7", label: "Adversarial Learning" },
  { value: "\u221E", label: "Strategy Evolution" },
];

const techStack = [
  { category: "Frontend", items: ["React 19", "TypeScript", "Vite 8", "Framer Motion", "Tailwind CSS 4", "Lucide Icons"] },
  { category: "Backend", items: ["Python 3.11+", "FastAPI", "Uvicorn", "Pydantic v2"] },
  { category: "AI / ML", items: ["PyTorch", "PyTorch Geometric (GNN)", "Ray RLlib", "LangChain", "OpenAI / Claude / Gemini"] },
  { category: "Infrastructure", items: ["Neo4j (Graph DB)", "Redis (Cache)", "ClickHouse (Analytics)", "Kafka (Streaming)", "Docker"] },
];

const timeline = [
  { phase: "Phase 1", title: "Core Simulation", desc: "Network topology, attack/defense execution, RL environment, basic agent framework" },
  { phase: "Phase 2", title: "Intelligence Layer", desc: "GNN risk prediction, LLM orchestration, strategic planning, incident analysis" },
  { phase: "Phase 3", title: "Dashboard & UI", desc: "React frontend, real-time visualization, topology canvas, co-evolution charts" },
  { phase: "Phase 4", title: "Real-World Ops", desc: "Data ingestion, live scanning, active mitigation, telemetry parsing, Cyber Range CLI" },
  { phase: "Phase 5", title: "Multi-Page Platform", desc: "Full routed website, analytics dashboard, documentation portal, agent architecture deep-dive" },
];

export default function AboutPage() {
  return (
    <PageTransition>
      <div className="p-6 md:p-10 max-w-[1000px] mx-auto">
        {/* Header */}
        <div className="mb-12 text-center">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1.0, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="w-16 h-16 rounded-2xl bg-[#00f5d4]/10 border border-[#00f5d4]/20 flex items-center justify-center mx-auto mb-6">
              <Shield size={28} className="text-[#00f5d4]" />
            </div>
            <h1 className="font-serif text-3xl md:text-5xl tracking-wide font-extralight text-white mb-3">
              Adaptive Intelligence Lab
            </h1>
            <p className="text-sm text-white/60 font-light leading-relaxed max-w-xl mx-auto">
              Building the next generation of autonomous cyber defense through
              competitive co-evolution, graph intelligence, and strategic AI reasoning.
            </p>
          </motion.div>
        </div>

        {/* Research Metrics */}
        <motion.div
          initial="hidden" whileInView="visible" viewport={{ once: true }}
          variants={{ hidden: {}, visible: { transition: { staggerChildren: 0.08, delayChildren: 0.2 } } }}
          className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-12"
        >
          {stats.map((metric, idx) => (
            <motion.div key={idx} variants={fadeUpVariants} className="text-center">
              <div className="text-3xl md:text-4xl font-light tracking-wide text-white mb-2 font-sans">{metric.value}</div>
              <div className="text-[10px] md:text-[11px] tracking-[0.2em] uppercase text-white/40 font-light">{metric.label}</div>
            </motion.div>
          ))}
        </motion.div>

        {/* Philosophy */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
          <div className="glassmorphism-card rounded-2xl p-8 mb-10 text-center">
            <p className="text-sm md:text-base tracking-wide leading-relaxed text-white/50 italic font-light font-serif">
              "Like natural ecosystems, resilient security emerges through adaptation,
              competition, cooperation, and continuous change."
            </p>
          </div>
        </motion.div>

        {/* Development Timeline */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
          <div className="glassmorphism-card rounded-2xl p-8 mb-10">
            <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90 mb-8">Development Timeline</h3>
            <div className="space-y-6">
              {timeline.map((item, idx) => (
                <div key={idx} className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className={`w-3 h-3 rounded-full border-2 ${idx <= 4 ? "border-[#00f5d4] bg-[#00f5d4]/20" : "border-white/20 bg-transparent"}`} />
                    {idx < timeline.length - 1 && <div className="w-px flex-1 bg-white/10 mt-1" />}
                  </div>
                  <div className="pb-4">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[9px] tracking-[0.2em] uppercase text-[#00f5d4] font-mono font-semibold">{item.phase}</span>
                      <span className="text-sm text-white/90 font-light">{item.title}</span>
                    </div>
                    <p className="text-xs text-white/45 font-light leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Tech Stack */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
          <div className="glassmorphism-card rounded-2xl p-8 mb-10">
            <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90 mb-6">Technology Stack</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {techStack.map((group, idx) => (
                <div key={idx}>
                  <h4 className="text-[10px] tracking-[0.2em] uppercase text-[#00f5d4]/70 mb-3 font-semibold">{group.category}</h4>
                  <div className="flex flex-wrap gap-2">
                    {group.items.map((item, iIdx) => (
                      <span key={iIdx} className="text-[10px] px-3 py-1.5 bg-white/[0.03] border border-white/8 rounded-lg text-white/60 font-mono">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Contact */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUpVariants}>
          <div className="glassmorphism-card rounded-2xl p-8 mb-10">
            <h3 className="text-xs font-semibold tracking-[0.2em] uppercase text-white/90 mb-6">Contact & Links</h3>
            <div className="flex flex-wrap gap-4">
              <a href="#" className="flex items-center gap-2 text-xs text-white/60 hover:text-white transition-colors bg-white/[0.03] border border-white/8 rounded-xl px-5 py-3">
                <GitBranch size={14} />
                <span>GitHub Repository</span>
                <ExternalLink size={10} className="opacity-40" />
              </a>
              <a href="#" className="flex items-center gap-2 text-xs text-white/60 hover:text-white transition-colors bg-white/[0.03] border border-white/8 rounded-xl px-5 py-3">
                <Mail size={14} />
                <span>Contact Lab</span>
                <ExternalLink size={10} className="opacity-40" />
              </a>
            </div>
          </div>
        </motion.div>

        {/* Footer */}
        <div className="text-center py-8 text-[9px] tracking-[0.3em] uppercase text-white/20 font-light border-t border-white/5">
          &copy; {new Date().getFullYear()} Adaptive Intelligence Lab. All rights reserved.
        </div>
      </div>
    </PageTransition>
  );
}
