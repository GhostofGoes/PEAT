import React from "react";
import { AbsoluteFill, interpolate, random, useCurrentFrame } from "remotion";
import { alpha, Theme, useTheme } from "../theme";
import { useLayout } from "../layout";

const PARTICLES = Array.from({ length: 46 }, (_, i) => ({
  x: random(`x${i}`),
  y: random(`y${i}`),
  r: 1.5 + random(`r${i}`) * 3,
  speed: 0.4 + random(`s${i}`) * 1.2,
  phase: random(`p${i}`) * Math.PI * 2,
}));

/** Mix two #RRGGBB colors; t=0 → a, t=1 → b. */
const mix = (a: string, b: string, t: number) => {
  const pa = parseInt(a.slice(1), 16);
  const pb = parseInt(b.slice(1), 16);
  const ch = (shift: number) => Math.round(interpolate(t, [0, 1], [(pa >> shift) & 255, (pb >> shift) & 255]));
  return `#${[16, 8, 0].map((s) => ch(s).toString(16).padStart(2, "0")).join("")}`;
};

/**
 * Persistent backdrop under every scene. Its style comes from the theme; in every style
 * the glow shifts from the danger color (the problem) to the accent (the solution).
 * `danger` is 0..1; `heat` scales how intense the danger glow is as pain points stack up.
 */
export const Background: React.FC<{ danger: number; heat: number }> = ({ danger, heat }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { width, height, isPortrait } = useLayout();
  const tint = mix(C.accent, C.danger, danger);
  const glowSize = isPortrait ? 1300 : Math.max(1500, width * 0.7);
  const pulse = 0.85 + 0.15 * Math.sin(frame / 22);
  const strength = C.dark ? 1 : 0.55;

  const glow = (color: string, a: number, cx = width / 2, cy = height * 0.42, size = glowSize) => (
    <div
      style={{
        position: "absolute",
        left: cx - size / 2,
        top: cy - size / 2,
        width: size,
        height: size,
        borderRadius: "50%",
        background: `radial-gradient(circle, ${alpha(color, a * strength)} 0%, ${alpha(color, 0)} 62%)`,
      }}
    />
  );

  return (
    <AbsoluteFill style={{ background: C.bg, overflow: "hidden" }}>
      {glow(C.danger, 0.34 * danger * heat * pulse)}
      {glow(C.accent, 0.3 * (1 - danger))}
      <Pattern C={C} tint={tint} frame={frame} width={width} height={height} danger={danger} />
      <AbsoluteFill style={{ background: `radial-gradient(ellipse at center, ${alpha(C.bg, 0)} 45%, ${C.vignette} 100%)` }} />
    </AbsoluteFill>
  );
};

const Pattern: React.FC<{ C: Theme; tint: string; frame: number; width: number; height: number; danger: number }> = ({
  C,
  tint,
  frame,
  width,
  height,
  danger,
}) => {
  const line = alpha(tint, 0.16);
  switch (C.bgStyle) {
    case "blueprint":
      return (
        <AbsoluteFill
          style={{
            backgroundImage: [
              `linear-gradient(${alpha(tint, 0.22)} 2px, transparent 2px)`,
              `linear-gradient(90deg, ${alpha(tint, 0.22)} 2px, transparent 2px)`,
              `linear-gradient(${alpha(tint, 0.08)} 1px, transparent 1px)`,
              `linear-gradient(90deg, ${alpha(tint, 0.08)} 1px, transparent 1px)`,
            ].join(", "),
            backgroundSize: "150px 150px, 150px 150px, 30px 30px, 30px 30px",
            backgroundPosition: `${(frame * 0.4) % 150}px ${(frame * 0.25) % 150}px`,
            opacity: 0.9,
          }}
        />
      );
    case "scanlines": {
      const sweep = ((frame * 4) % (height + 400)) - 200;
      return (
        <>
          <AbsoluteFill
            style={{
              backgroundImage: `linear-gradient(${alpha(tint, 0.07)} 1px, transparent 1px), linear-gradient(90deg, ${alpha(tint, 0.07)} 1px, transparent 1px)`,
              backgroundSize: "120px 120px",
            }}
          />
          <AbsoluteFill style={{ backgroundImage: `repeating-linear-gradient(0deg, rgba(0,0,0,0.22) 0px, rgba(0,0,0,0.22) 2px, transparent 2px, transparent 5px)` }} />
          <div style={{ position: "absolute", left: 0, right: 0, top: sweep, height: 200, background: `linear-gradient(transparent, ${alpha(tint, 0.06)}, transparent)` }} />
        </>
      );
    }
    case "aurora":
      return (
        <>
          {[0, 1, 2].map((i) => {
            const t = frame / 90 + i * 2.1;
            const size = Math.max(width, height) * 0.7;
            const colors = [tint, C.accent, danger > 0.5 ? C.warn : "#7C9CFF"];
            return (
              <div
                key={i}
                style={{
                  position: "absolute",
                  left: width * (0.2 + 0.3 * i) + Math.sin(t) * 120 - size / 2,
                  top: height * (0.3 + 0.2 * (i % 2)) + Math.cos(t * 0.8) * 90 - size / 2,
                  width: size,
                  height: size,
                  borderRadius: "50%",
                  background: `radial-gradient(circle, ${alpha(colors[i], 0.16)} 0%, ${alpha(colors[i], 0)} 65%)`,
                }}
              />
            );
          })}
          <AbsoluteFill style={{ backgroundImage: `radial-gradient(${alpha(C.text, 0.07)} 1.5px, transparent 1.5px)`, backgroundSize: "36px 36px" }} />
        </>
      );
    case "dots":
      return (
        <>
          <AbsoluteFill
            style={{
              backgroundImage: `radial-gradient(${alpha(tint, 0.35)} 2px, transparent 2.5px)`,
              backgroundSize: "44px 44px",
              backgroundPosition: `${(frame * 0.6) % 44}px 0px`,
              maskImage: "radial-gradient(ellipse at center, black 20%, transparent 75%)",
              WebkitMaskImage: "radial-gradient(ellipse at center, black 20%, transparent 75%)",
            }}
          />
          {[0, 1].map((i) => {
            const x = ((frame * (2 + i) + i * width * 0.5) % (width + 800)) - 400;
            return (
              <div
                key={i}
                style={{
                  position: "absolute",
                  left: x,
                  top: 0,
                  bottom: 0,
                  width: 3,
                  background: `linear-gradient(transparent, ${alpha(tint, 0.35)}, transparent)`,
                  transform: "skewX(-20deg)",
                }}
              />
            );
          })}
        </>
      );
    case "grid":
    default:
      return (
        <>
          <div
            style={{
              position: "absolute",
              left: -width,
              right: -width,
              bottom: -height * 0.15,
              height: height * 0.75,
              transform: "perspective(700px) rotateX(62deg)",
              transformOrigin: "bottom center",
              backgroundImage: `linear-gradient(${line} 1.5px, transparent 1.5px), linear-gradient(90deg, ${line} 1.5px, transparent 1.5px)`,
              backgroundSize: "90px 90px",
              backgroundPosition: `0px ${(frame * 1.2) % 90}px`,
              maskImage: "linear-gradient(to top, black 10%, transparent 85%)",
              WebkitMaskImage: "linear-gradient(to top, black 10%, transparent 85%)",
              opacity: 0.9,
            }}
          />
          {PARTICLES.map((p, i) => {
            const y = (((p.y * height - frame * p.speed) % height) + height) % height;
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
                  background: tint,
                  opacity: 0.12 + 0.25 * Math.abs(Math.sin(frame / 30 + p.phase)),
                }}
              />
            );
          })}
        </>
      );
  }
};
