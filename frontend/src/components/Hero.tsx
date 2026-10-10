import React from 'react';
import { useNavigate } from 'react-router-dom';
import Navbar from './Navbar';
import AnimatedHeading from './AnimatedHeading';
import FadeIn from './FadeIn';

export const Hero: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="relative min-h-screen h-screen overflow-hidden bg-black text-white flex flex-col">
      {/* Background Video (Raw video, no overlays or dimming) */}
      <video
        autoPlay
        loop
        muted
        playsInline
        aria-hidden="true"
        className="absolute inset-0 w-full h-full object-cover z-0"
        src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260403_050628_c4e32401-fab4-4a27-b7a8-6e9291cd5959.mp4"
      />

      {/* Floating Liquid-Glass Navbar at top */}
      <Navbar />

      {/* Hero Content Area anchored near bottom of viewport */}
      <main className="relative z-10 flex-1 flex flex-col justify-end px-6 md:px-12 lg:px-16 pb-12 lg:pb-16">
        <div className="lg:grid lg:grid-cols-2 lg:items-end gap-10">
          {/* Left Column */}
          <div className="max-w-4xl">
            <AnimatedHeading
              text={`Autonomous defense\nfor evolving threats.`}
              initialDelay={200}
            />

            <FadeIn delay={800} duration={1000}>
              <p className="text-base md:text-lg text-gray-300 mb-5 max-w-2xl leading-relaxed">
                A research platform where autonomous attackers, defenders, graph intelligence, and LLM-driven agents compete across realistic enterprise environments.
              </p>
            </FadeIn>

            <FadeIn delay={1200} duration={1000}>
              <div className="flex flex-wrap gap-4">
                <button
                  onClick={() => navigate('/simulation')}
                  className="bg-white text-black px-8 py-3 rounded-lg font-medium transition-colors duration-300 hover:bg-gray-100 cursor-pointer"
                >
                  Run Simulation
                </button>
                <button
                  onClick={() => navigate('/docs')}
                  className="liquid-glass border border-white/20 text-white px-8 py-3 rounded-lg font-medium transition-all duration-300 hover:bg-white hover:text-black cursor-pointer"
                >
                  Explore Architecture
                </button>
              </div>
            </FadeIn>
          </div>

          {/* Right Column */}
          <div className="flex items-end justify-start lg:justify-end mt-8 lg:mt-0">
            <FadeIn delay={1400} duration={1000}>
              <div>
                <div className="text-[10px] md:text-xs uppercase tracking-[0.18em] text-gray-300 mb-2">
                  AUTONOMOUS CYBER RANGE // ONLINE
                </div>
                <div className="liquid-glass border border-white/20 px-6 py-3 rounded-xl">
                  <span className="text-lg md:text-xl lg:text-2xl font-light tracking-tight text-white">
                    Attack. Detect. Contain. Adapt.
                  </span>
                </div>
              </div>
            </FadeIn>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Hero;
