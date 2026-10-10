import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Home, Activity, Users, BarChart3, FileText, Info,
  Menu, X, Shield, ChevronRight, CheckCircle2
} from "lucide-react";

const navItems = [
  { path: "/", label: "Home", icon: Home },
  { path: "/simulation", label: "Simulation", icon: Activity },
  { path: "/agents", label: "Agents", icon: Users },
  { path: "/analytics", label: "Analytics", icon: BarChart3 },
  { path: "/docs", label: "Docs", icon: FileText },
  { path: "/about", label: "About", icon: Info },
];

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  if (location.pathname === "/") {
    return <Outlet />;
  }

  const currentSegment = location.pathname.replace('/', '').toUpperCase() || 'DASHBOARD';

  return (
    <div className="layout-root">
      {/* Desktop Sidebar */}
      <aside className="sidebar-desktop">
        <div className="sidebar-brand">
          <Shield size={18} className="text-[#00f5d4]" />
          <span className="sidebar-brand-text">AMCDS</span>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive =
              item.path === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(item.path);
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`sidebar-link ${isActive ? "sidebar-link-active" : ""}`}
              >
                <div className="sidebar-link-indicator" />
                <Icon size={16} />
                <span>{item.label}</span>
                {isActive && (
                  <ChevronRight size={12} className="ml-auto opacity-40" />
                )}
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-footer-dot" />
          <span>System Online</span>
        </div>
      </aside>

      {/* Mobile Header */}
      <header className="mobile-header">
        <div className="flex items-center space-x-2">
          <Shield size={16} className="text-[#00f5d4]" />
          <span className="text-[10px] tracking-[0.3em] uppercase text-white/80 font-light">
            AMCDS
          </span>
        </div>
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="text-white/70 hover:text-white transition-colors cursor-pointer"
          aria-label="Toggle navigation"
        >
          {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </header>

      {/* Mobile Navigation Drawer */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="mobile-backdrop"
              onClick={() => setSidebarOpen(false)}
            />
            <motion.nav
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: "spring", stiffness: 300, damping: 30 }}
              className="mobile-drawer"
            >
              <div className="p-6 border-b border-white/5 flex items-center space-x-2">
                <Shield size={18} className="text-[#00f5d4]" />
                <span className="text-xs tracking-[0.2em] uppercase text-white/80 font-light">
                  Adaptive Intelligence
                </span>
              </div>
              <div className="p-4 space-y-1">
                {navItems.map((item) => {
                  const Icon = item.icon;
                  const isActive =
                    item.path === "/"
                      ? location.pathname === "/"
                      : location.pathname.startsWith(item.path);
                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      onClick={() => setSidebarOpen(false)}
                      className={`sidebar-link ${isActive ? "sidebar-link-active" : ""}`}
                    >
                      <div className="sidebar-link-indicator" />
                      <Icon size={16} />
                      <span>{item.label}</span>
                    </NavLink>
                  );
                })}
              </div>
            </motion.nav>
          </>
        )}
      </AnimatePresence>

      {/* Main Content Area with Glass Navbar Header */}
      <main className="main-content p-6">
        <div className="liquid-glass rounded-xl px-5 py-3 flex items-center justify-between mb-6 border border-white/10 shadow-lg">
          <div className="flex items-center space-x-3">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-semibold tracking-widest text-white font-mono uppercase">
              AMCDS // {currentSegment}
            </span>
            <span className="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 flex items-center gap-1">
              <CheckCircle2 size={10} /> Active
            </span>
          </div>

          <div className="hidden md:flex items-center gap-6 text-xs">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `transition-colors duration-200 ${isActive ? "text-[#00f5d4] font-semibold" : "text-white/70 hover:text-white"}`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>

          <button
            onClick={() => navigate('/simulation')}
            className="bg-white text-black px-4 py-1.5 rounded-lg text-xs font-medium transition-colors duration-300 hover:bg-gray-100 cursor-pointer"
          >
            Launch Simulator
          </button>
        </div>

        <Outlet />
      </main>
    </div>
  );
}
