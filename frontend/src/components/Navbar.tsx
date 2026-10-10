import React from 'react';
import { Link, useNavigate } from 'react-router-dom';

export const Navbar: React.FC = () => {
  const navigate = useNavigate();

  return (
    <header className="px-6 md:px-12 lg:px-16 pt-6 relative z-20">
      <nav className="liquid-glass rounded-xl px-4 py-2 flex items-center justify-between">
        {/* Navbar Left */}
        <Link to="/" className="flex items-center gap-2.5 text-white">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-xl md:text-2xl font-semibold tracking-tight">
            AMCDS
          </span>
        </Link>

        {/* Navbar Center */}
        <div className="hidden md:flex items-center gap-8 text-sm">
          <Link
            to="/"
            className="text-white transition-colors duration-300 hover:text-gray-300"
          >
            Overview
          </Link>
          <Link
            to="/simulation"
            className="text-white transition-colors duration-300 hover:text-gray-300"
          >
            Simulation
          </Link>
          <Link
            to="/analytics"
            className="text-white transition-colors duration-300 hover:text-gray-300"
          >
            Intelligence
          </Link>
          <Link
            to="/docs"
            className="text-white transition-colors duration-300 hover:text-gray-300"
          >
            Research
          </Link>
        </div>

        {/* Navbar Right */}
        <button
          onClick={() => navigate('/simulation')}
          className="bg-white text-black px-6 py-2 rounded-lg text-sm font-medium transition-colors duration-300 hover:bg-gray-100 cursor-pointer"
        >
          Launch Simulator
        </button>
      </nav>
    </header>
  );
};

export default Navbar;
