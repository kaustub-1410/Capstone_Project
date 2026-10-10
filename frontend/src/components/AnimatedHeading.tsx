import React, { useState, useEffect } from 'react';

interface AnimatedHeadingProps {
  text: string;
  initialDelay?: number;
  className?: string;
}

export const AnimatedHeading: React.FC<AnimatedHeadingProps> = ({
  text,
  initialDelay = 200,
  className = '',
}) => {
  const [isAnimated, setIsAnimated] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsAnimated(true);
    }, initialDelay);
    return () => clearTimeout(timer);
  }, [initialDelay]);

  const lines = text.split('\n');
  const charDelay = 30;
  let cumulativeCharCount = 0;

  return (
    <h1
      className={`text-4xl md:text-5xl lg:text-6xl xl:text-7xl font-normal mb-4 leading-[0.98] text-white ${className}`}
      style={{ letterSpacing: '-0.04em' }}
    >
      {lines.map((line, lineIndex) => {
        const lineStartCharIndex = cumulativeCharCount;
        cumulativeCharCount += line.length;

        return (
          <span key={lineIndex} className="block">
            {line.split('').map((char, charIndex) => {
              const globalIndex = lineStartCharIndex + charIndex;
              const delay = initialDelay + globalIndex * charDelay;

              return (
                <span
                  key={charIndex}
                  className="inline-block"
                  style={{
                    opacity: isAnimated ? 1 : 0,
                    transform: isAnimated ? 'translateX(0)' : 'translateX(-18px)',
                    transitionProperty: 'opacity, transform',
                    transitionDuration: '500ms',
                    transitionTimingFunction: 'cubic-bezier(0.16, 1, 0.3, 1)',
                    transitionDelay: `${delay}ms`,
                  }}
                >
                  {char === ' ' ? '\u00A0' : char}
                </span>
              );
            })}
          </span>
        );
      })}
    </h1>
  );
};

export default AnimatedHeading;
