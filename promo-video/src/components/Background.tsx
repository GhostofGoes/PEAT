import React from "react";
import { AbsoluteFill, interpolate, random, useCurrentFrame } from "remotion";
import { C } from "../theme";
import { useLayout } from "../layout";

const PARTICLES = Array.from({ length: 46 }, (_, i) => ({
  x: random(`x${i}`),
  y: random(`y${i}`),
  r: 1.5 + random(`r${i}`) * 3,
  speed: 0.4 + random(`s${i}`) * 1.2,
  phase: random(`p${i}`) * Math.PI * 2,
}));

/**
 * Persistent backdrop under every scene: perspective grid, drifting particles and a
 * glow that shifts from alarm red (the problem) to PEAT cyan (the solution).
 * `danger` is 0..1; `heat` scales how intense the red is as pain points stack up.
 */
export const Background: React.FC<{ danger: number; heat: number }> = ({ danger, heat }) => {
  const frame = useCurrentFrame();
  const { width, height, isPortrait } = useLayout();
  const red = danger * heat;
  const cyan = 1 - danger;
  const glowSize = isPortrait ? 1300 : 1500;
  const gridColor = `rgba(${Math.round(interpolate(danger, [0, 1], [79, 248]))}, ${Math.round(interpolate(danger, [0, 1], [216, 113]))}, ${Math.round(interpolate(danger, [0, 1], [242, 113]))}, 0.16)`;
  const pulse = 0.85 + 0.15 * Math.sin(frame / 22);

  return (
    <AbsoluteFill style={{ background: C.bg, overflow: "hidden" }}>
      {/* glows */}
      <div
        style={{
          position: "absolute",
          left: width / 2 - glowSize / 2,
          top: height * 0.42 - glowSize / 2,
          width: glowSize,
          height: glowSize,
          borderRadius: "50%",
          background: `radial-gradient(circle, rgba(239,68,68,${0.34 * red * pulse}) 0%, rgba(239,68,68,0) 62%)`,
        }}
      />
      <div
        style={{
          position: "absolute",
          left: width / 2 - glowSize / 2,
          top: height * 0.42 - glowSize / 2,
          width: glowSize,
          height: glowSize,
          borderRadius: "50%",
          background: `radial-gradient(circle, rgba(0,173,208,${0.3 * cyan}) 0%, rgba(0,173,208,0) 62%)`,
        }}
      />
      {/* perspective grid floor */}
      <div
        style={{
          position: "absolute",
          left: -width,
          right: -width,
          bottom: -height * 0.15,
          height: height * 0.75,
          transform: "perspective(700px) rotateX(62deg)",
          transformOrigin: "bottom center",
          backgroundImage: `linear-gradient(${gridColor} 1.5px, transparent 1.5px), linear-gradient(90deg, ${gridColor} 1.5px, transparent 1.5px)`,
          backgroundSize: "90px 90px",
          backgroundPosition: `0px ${(frame * 1.2) % 90}px`,
          maskImage: "linear-gradient(to top, black 10%, transparent 85%)",
          WebkitMaskImage: "linear-gradient(to top, black 10%, transparent 85%)",
          opacity: 0.9,
        }}
      />
      {/* particles */}
      {PARTICLES.map((p, i) => {
        const y = ((p.y * height - frame * p.speed) % height + height) % height;
        const x = p.x * width + Math.sin(frame / 40 + p.phase) * 18;
        return (
          <div
            key={i}
            style={{
              position: "absolute",
              left: x,
              top: y,
              width: p.r * 2,
              height: p.r * 2,
              borderRadius: "50%",
              background: danger > 0.5 ? C.redSoft : C.cyanBright,
              opacity: 0.12 + 0.25 * Math.abs(Math.sin(frame / 30 + p.phase)),
            }}
          />
        );
      })}
      {/* vignette */}
      <AbsoluteFill style={{ background: "radial-gradient(ellipse at center, rgba(0,0,0,0) 45%, rgba(0,0,0,0.7) 100%)" }} />
    </AbsoluteFill>
  );
};
