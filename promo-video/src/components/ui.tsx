import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { alpha, useTheme } from "../theme";
import { useLayout } from "../layout";

/** Spring progress (0 → 1) that starts at `delay` frames. */
export const useEnter = (delay = 0, config: { damping?: number; mass?: number; stiffness?: number } = { damping: 200 }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({ frame: frame - delay, fps, config });
};

export const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

/** Full-frame column layout used by most non-feature scenes. */
export const Stage: React.FC<{ children: React.ReactNode; gap?: number; center?: boolean }> = ({ children, gap = 48, center }) => {
  const { padding } = useLayout();
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: center ? "center" : "stretch", gap }}>
      {children}
    </AbsoluteFill>
  );
};

/** Fades, lifts and de-blurs its children into place. */
export const Rise: React.FC<{
  delay?: number;
  y?: number;
  scaleFrom?: number;
  style?: React.CSSProperties;
  children: React.ReactNode;
}> = ({ delay = 0, y = 40, scaleFrom = 1, style, children }) => {
  const p = useEnter(delay);
  return (
    <div
      style={{
        opacity: p,
        transform: `translateY(${(1 - p) * y}px) scale(${interpolate(p, [0, 1], [scaleFrom, 1])})`,
        filter: `blur(${(1 - p) * 8}px)`,
        ...style,
      }}
    >
      {children}
    </div>
  );
};

/**
 * Word-by-word headline. Wrap accent words in asterisks: "Attacks now hit *the controller*".
 */
export const Words: React.FC<{
  text: string;
  delay?: number;
  stagger?: number;
  size: number;
  accent?: string;
  color?: string;
  weight?: number;
  align?: "left" | "center";
  style?: React.CSSProperties;
}> = ({ text, delay = 0, stagger = 4, size, accent, color, weight, align = "left", style }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const accentColor = accent ?? C.accentHi;
  let inAccent = false;
  const words = text.split(" ").map((raw) => {
    if (raw.startsWith("*")) inAccent = true;
    const word = raw.replace(/\*/g, "");
    const accented = inAccent;
    if (/\*[.,!?:;]?$/.test(raw)) inAccent = false;
    return { word, accented };
  });
  return (
    <div
      style={{
        fontFamily: C.font,
        fontSize: size,
        fontWeight: weight ?? C.headWeight,
        lineHeight: 1.08,
        letterSpacing: C.tracking,
        color: color ?? C.text,
        textAlign: align,
        display: "flex",
        flexWrap: "wrap",
        justifyContent: align === "center" ? "center" : "flex-start",
        columnGap: size * 0.26,
        ...style,
      }}
    >
      {words.map(({ word, accented }, i) => {
        const p = spring({ frame: frame - delay - i * stagger, fps, config: { damping: 200 } });
        return (
          <span
            key={i}
            style={{
              display: "inline-block",
              opacity: p,
              transform: `translateY(${(1 - p) * size * 0.45}px)`,
              filter: `blur(${(1 - p) * 6}px)`,
              color: accented ? accentColor : undefined,
              textShadow: accented && C.dark ? `0 0 ${size * 0.5}px ${alpha(accentColor, 0.33)}` : undefined,
            }}
          >
            {word}
          </span>
        );
      })}
    </div>
  );
};

/** Small uppercase label with an accent bar, e.g. "01 — THE THREAT". */
export const Eyebrow: React.FC<{ label: string; color?: string; delay?: number; size?: number; center?: boolean }> = ({
  label,
  color,
  delay = 0,
  size = 26,
  center,
}) => {
  const C = useTheme();
  const p = useEnter(delay);
  const c = color ?? C.accentHi;
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: center ? "center" : "flex-start",
        gap: 16,
        opacity: p,
        fontFamily: C.font,
        fontWeight: 700,
        fontSize: size,
        letterSpacing: "0.24em",
        color: c,
      }}
    >
      <div style={{ width: 56 * p, height: 4, borderRadius: 2, background: c, boxShadow: C.dark ? `0 0 16px ${c}` : undefined }} />
      {label}
    </div>
  );
};

export const Panel: React.FC<{ style?: React.CSSProperties; glow?: string; children: React.ReactNode }> = ({ style, glow, children }) => {
  const C = useTheme();
  const base: React.CSSProperties =
    C.panelStyle === "outline"
      ? { background: C.panel, border: `2px solid ${glow ? alpha(glow, 0.8) : C.border}`, boxShadow: glow ? `0 0 40px ${alpha(glow, 0.18)}` : undefined }
      : C.panelStyle === "solid"
        ? { background: C.bg2, border: `1px solid ${glow ? alpha(glow, 0.55) : C.border}`, boxShadow: `0 24px 60px ${C.shadow}${glow ? `, 0 0 50px ${alpha(glow, 0.2)}` : ""}` }
        : C.panelStyle === "soft"
          ? { background: C.panel, border: `1px solid ${glow ? alpha(glow, 0.45) : C.border}`, boxShadow: `0 20px 50px ${C.shadow}${glow ? `, 0 0 0 4px ${alpha(glow, 0.12)}` : ""}` }
          : { background: C.panel, border: `1px solid ${glow ? alpha(glow, 0.4) : C.border}`, boxShadow: `0 30px 80px ${C.shadow}${glow ? `, 0 0 60px ${alpha(glow, 0.2)}` : ""}` };
  return <div style={{ borderRadius: C.radius, ...base, ...style }}>{children}</div>;
};

export type TermLine = { text: string; at: number; color?: string; bold?: boolean };

/** Terminal window. The first line is typed out; the rest appear at their `at` frame. */
export const Terminal: React.FC<{
  title: string;
  command: string;
  commandAt: number;
  lines: TermLine[];
  fontSize: number;
  style?: React.CSSProperties;
}> = ({ title, command, commandAt, lines, fontSize, style }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const typed = Math.max(0, Math.min(command.length, Math.floor((frame - commandAt) * 1.6)));
  const typing = typed < command.length;
  const cursorOn = Math.floor(frame / 12) % 2 === 0;
  return (
    <Panel glow={C.accent} style={{ overflow: "hidden", ...style }}>
      <div
        style={{
          height: fontSize * 2.2,
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "0 22px",
          background: C.subtle,
          borderBottom: `1px solid ${C.border}`,
        }}
      >
        {["#FF5F57", "#FEBC2E", "#28C840"].map((c) => (
          <div key={c} style={{ width: 14, height: 14, borderRadius: 7, background: c }} />
        ))}
        <div style={{ flex: 1, textAlign: "center", fontFamily: C.mono, fontSize: fontSize * 0.75, color: C.dim }}>{title}</div>
      </div>
      <div style={{ padding: `${fontSize * 1.1}px ${fontSize * 1.3}px`, fontFamily: C.mono, fontSize, lineHeight: 1.65 }}>
        <div style={{ color: C.text, whiteSpace: "pre" }}>
          <span style={{ color: C.accentHi }}>$ </span>
          {command.slice(0, typed)}
          {typing && cursorOn ? <span style={{ background: C.accentHi }}> </span> : null}
        </div>
        {lines.map((l, i) => {
          const o = interpolate(frame, [l.at, l.at + 6], [0, 1], clamp);
          return (
            <div key={i} style={{ opacity: o, transform: `translateX(${(1 - o) * -12}px)`, color: l.color ?? C.muted, fontWeight: l.bold ? 600 : 400, whiteSpace: "pre" }}>
              {l.text}
            </div>
          );
        })}
      </div>
    </Panel>
  );
};

/** Pill-shaped chip. */
export const Chip: React.FC<{ color?: string; delay?: number; size?: number; icon?: React.ReactNode; children: React.ReactNode }> = ({
  color,
  delay = 0,
  size = 28,
  icon,
  children,
}) => {
  const C = useTheme();
  const c = color ?? C.accentHi;
  const p = useEnter(delay, { damping: 14, mass: 0.6 });
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: size * 0.4,
        padding: `${size * 0.42}px ${size * 0.85}px`,
        borderRadius: C.radius <= 6 ? C.radius : 999,
        border: `2px solid ${alpha(c, 0.55)}`,
        background: alpha(c, C.dark ? 0.1 : 0.08),
        color: c,
        fontFamily: C.font,
        fontWeight: 700,
        fontSize: size,
        opacity: Math.min(1, p * 1.5),
        transform: `scale(${interpolate(p, [0, 1], [0.6, 1])})`,
        whiteSpace: "nowrap",
      }}
    >
      {icon}
      {children}
    </div>
  );
};

/** Rounded square holding an icon, used next to feature eyebrows. */
export const IconTile: React.FC<{ children: React.ReactNode; size?: number }> = ({ children, size = 76 }) => {
  const C = useTheme();
  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: Math.min(C.radius, 20),
        background: alpha(C.accent, 0.13),
        border: `2px solid ${alpha(C.accent, 0.55)}`,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {children}
    </div>
  );
};
