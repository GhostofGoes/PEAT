import React from "react";
import { AbsoluteFill, Img, interpolate, random, spring, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import {
  ArrowDown,
  ArrowRight,
  BookOpen,
  Braces,
  Cable,
  CircleCheck,
  Cpu,
  Database,
  FileCode2,
  GitCompareArrows,
  HardDrive,
  ScrollText,
  SlidersHorizontal,
  Terminal as TerminalIcon,
} from "lucide-react";
import { alpha, useTheme } from "../theme";
import { useLayout } from "../layout";
import { useCopy, useCue } from "../timeline";
import { Chip, clamp, Eyebrow, IconTile, Panel, Rise, Terminal, Words, useEnter } from "../components/ui";

const GitHubMark: React.FC<{ size: number; color: string }> = ({ size, color }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill={color} aria-hidden>
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
  </svg>
);

export const Logo: React.FC<{ height: number; delay?: number }> = ({ height, delay = 0 }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - delay, fps, config: { damping: 12, mass: 0.8 } });
  const ring = interpolate(frame - delay, [4, 40], [0, 1], clamp);
  return (
    <div style={{ position: "relative", height, width: height * (843 / 900), display: "flex", justifyContent: "center", alignItems: "center" }}>
      <div
        style={{
          position: "absolute",
          width: height * 1.5,
          height: height * 1.5,
          borderRadius: "50%",
          border: `3px solid ${C.accent}`,
          opacity: (1 - ring) * 0.8,
          transform: `scale(${0.5 + ring * 0.9})`,
        }}
      />
      <div
        style={{
          position: "absolute",
          width: height * 1.3,
          height: height * 1.3,
          borderRadius: "50%",
          background: `radial-gradient(circle, ${alpha(C.accent, C.dark ? 0.25 : 0.15)} 0%, transparent 65%)`,
          opacity: p,
        }}
      />
      <Img
        src={staticFile("peat-logo.png")}
        style={{
          height,
          opacity: Math.min(1, p * 1.4),
          transform: `scale(${interpolate(p, [0, 1], [0.55, 1])})`,
          filter: `blur(${(1 - Math.min(1, p)) * 12}px)${C.dark ? ` drop-shadow(0 0 40px ${alpha(C.accent, 0.33)})` : ""}`,
        }}
      />
    </div>
  );
};

/* ---------- Reveal ---------- */

export const RevealScene: React.FC = () => {
  const C = useTheme();
  const { isPortrait, padding, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: pick(36, 56) }}>
      <Logo height={pick(400, 480)} delay={8} />
      <Words text={copy.str("title")} delay={cue("title", 0.25)} stagger={4} size={pick(76, 76)} align="center" style={{ maxWidth: isPortrait ? 900 : 1600 }} />
      <Rise delay={cue("sub", 0.75)} y={20}>
        <div style={{ fontFamily: C.font, fontSize: pick(36, 36), color: C.muted, textAlign: "center", fontWeight: 500 }}>
          Built at <span style={{ color: C.text, fontWeight: 700 }}>Sandia National Laboratories</span>
        </div>
      </Rise>
    </AbsoluteFill>
  );
};

/* ---------- shared feature layout ---------- */

export const Feature: React.FC<{
  icon: React.ReactNode;
  visual: React.ReactNode;
  textWidth?: number;
}> = ({ icon, visual, textWidth = 600 }) => {
  const C = useTheme();
  const { isPortrait, isUltrawide, padding, pick } = useLayout();
  const copy = useCopy();
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: isPortrait ? "column" : "row", alignItems: "center", justifyContent: "center", gap: pick(80, 70) }}>
      <div style={{ width: isPortrait ? "100%" : textWidth + (isUltrawide ? 100 : 0), flexShrink: 0, display: "flex", flexDirection: "column", gap: 26 }}>
        <Rise delay={2} y={20}>
          <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
            <IconTile>{icon}</IconTile>
            <Eyebrow label={copy.str("step")} delay={4} size={30} />
          </div>
        </Rise>
        <Words text={copy.str("title")} delay={8} stagger={3} size={pick(76, 74)} />
        <Rise delay={20} y={20}>
          <div style={{ fontFamily: C.font, fontSize: pick(34, 34), color: C.muted, lineHeight: 1.35 }}>{copy.str("sub")}</div>
        </Rise>
      </div>
      <div style={{ flex: isPortrait ? "none" : 1, width: isPortrait ? "100%" : undefined, display: "flex", justifyContent: "center" }}>{visual}</div>
    </AbsoluteFill>
  );
};

/* ---------- Scan ---------- */

export const ScanScene: React.FC = () => {
  const C = useTheme();
  const { pick } = useLayout();
  const cue = useCue();
  const p = useEnter(4);
  const at = Math.max(30, cue("results", 0.4));
  const rows = [
    ["192.0.2.10", "SEL-451", "relay"],
    ["192.0.2.21", "Modicon M340", "PLC"],
    ["192.0.2.33", "ControlLogix", "PLC"],
    ["192.0.2.47", "Sage 3030M", "RTU"],
  ];
  const pad = (s: string, n: number) => s.padEnd(n, " ");
  return (
    <Feature
      icon={<TerminalIcon size={40} color={C.accentHi} />}
      visual={
        <div style={{ width: "100%", transform: `perspective(1400px) rotateY(${pick(-9, 0)}deg) rotateX(${pick(4, 6)}deg) scale(${0.92 + p * 0.08})`, opacity: p }}>
          <Terminal
            title="peat — scan"
            command="peat scan -i 192.0.2.0/24"
            commandAt={6}
            fontSize={pick(34, 32)}
            lines={[
              { text: "probing 254 hosts…", at: 26, color: C.dim },
              ...rows.map((r, i) => ({ text: `${pad(r[0], 13)}${pad(r[1], 14)}${pad(r[2], 6)}✔`, at: at + i * 8, color: C.text })),
              { text: "4 OT devices identified", at: at + 40, color: C.accentHi, bold: true },
            ]}
          />
        </div>
      }
    />
  );
};

/* ---------- Pull ---------- */

const ARTIFACTS = [
  { label: "Logic", detail: "ladder · ST · protection", Icon: FileCode2, cue: "logic", f: 0.1 },
  { label: "Configs", detail: "IPs · services · users", Icon: SlidersHorizontal, cue: "configs", f: 0.3 },
  { label: "Logs", detail: "SER · audit · events", Icon: ScrollText, cue: "logs", f: 0.45 },
  { label: "Firmware", detail: "images · hashes", Icon: HardDrive, cue: "firmware", f: 0.6 },
];

export const PullScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { pick } = useLayout();
  const cue = useCue();
  const linkAt = cue("link", 0.8);
  return (
    <Feature
      icon={<Cpu size={40} color={C.accentHi} />}
      textWidth={500}
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 30, width: "100%", maxWidth: 1060 }}>
          <div style={{ display: "grid", gridTemplateColumns: pick("1fr 1fr", "1fr"), gap: 26 }}>
            {ARTIFACTS.map(({ label, detail, Icon, cue: c, f }) => {
              const at = cue(c, f);
              const p = spring({ frame: frame - at, fps, config: { damping: 13, mass: 0.7 } });
              const done = frame > at + 16;
              return (
                <div key={label} style={{ opacity: Math.min(1, p * 1.4), transform: `translateY(${(1 - p) * 60}px) scale(${interpolate(p, [0, 1], [0.8, 1])})` }}>
                  <Panel glow={done ? C.accent : undefined} style={{ padding: pick("40px 34px", "34px 36px"), display: "flex", alignItems: "center", gap: 26 }}>
                    <Icon size={72} color={C.accentHi} strokeWidth={1.6} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontFamily: C.font, fontWeight: C.headWeight, fontSize: pick(50, 52), color: C.text }}>{label}</div>
                      <div style={{ fontFamily: C.font, fontSize: pick(28, 30), color: C.muted }}>{detail}</div>
                    </div>
                    <CircleCheck size={46} color={C.ok} style={{ opacity: done ? 1 : 0.15 }} />
                  </Panel>
                </div>
              );
            })}
          </div>
          <div style={{ display: "flex", gap: 20, justifyContent: "center" }}>
            <Chip delay={linkAt} size={pick(34, 36)} icon={<Cable size={36} />}>
              Ethernet
            </Chip>
            <Chip delay={linkAt + 12} size={pick(34, 36)} icon={<Cable size={36} />}>
              Serial (RS-232)
            </Chip>
          </div>
        </div>
      }
    />
  );
};

/* ---------- Parse ---------- */

const HEX = Array.from({ length: 7 }, (_, r) =>
  Array.from({ length: 8 }, (_, c) => Math.floor(random(`h${r}-${c}`) * 256).toString(16).padStart(2, "0").toUpperCase()).join(" "),
);

const JSON_LINES: Array<[string, string?]> = [
  ["{"],
  ['  "host": {'],
  ['    "ip": ', '"192.0.2.10"'],
  ['    "description": {'],
  ['      "vendor": ', '{ "id": "SEL" }'],
  ['      "model": ', '"451"'],
  ["    },"],
  ['    "firmware": ', '{ "version": "R322" }'],
  ['    "logic": ', '{ "hash": "9f2c…e71a" }'],
  ["  }"],
  ["}"],
];

export const ParseScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { isPortrait, pick } = useLayout();
  const cue = useCue();
  const flowAt = cue("flow", 0.5);
  const flow = interpolate(frame, [flowAt - 20, flowAt + 6], [0, 1], clamp);
  const fs = pick(25, 32);
  const Arrow = isPortrait ? ArrowDown : ArrowRight;
  return (
    <Feature
      icon={<Braces size={40} color={C.accentHi} />}
      textWidth={500}
      visual={
        <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", alignItems: "center", gap: 22, width: "100%" }}>
          <Rise delay={14} style={{ flex: 1, width: isPortrait ? "100%" : undefined }}>
            <Panel style={{ padding: 32 }}>
              <div style={{ fontFamily: C.font, fontSize: 26, fontWeight: 700, color: C.warn, marginBottom: 14, letterSpacing: "0.12em" }}>PROPRIETARY BLOB</div>
              {HEX.slice(0, isPortrait ? 5 : 7).map((row, i) => (
                <div key={i} style={{ fontFamily: C.mono, fontSize: fs, color: C.dim, lineHeight: 1.6, whiteSpace: "pre", opacity: 1 - flow * 0.5 }}>
                  {row}
                </div>
              ))}
              <div style={{ fontFamily: C.mono, fontSize: 24, color: C.muted, marginTop: 12 }}>.l5x · .rdb · SET_ALL.TXT · UMAS</div>
            </Panel>
          </Rise>
          <Arrow size={64} color={C.accentHi} style={{ opacity: flow, flexShrink: 0 }} />
          <div style={{ flex: 1.25, width: isPortrait ? "100%" : undefined, opacity: flow, transform: `translateX(${(1 - flow) * 40}px)` }}>
            <Panel glow={C.accent} style={{ padding: 32 }}>
              <div style={{ fontFamily: C.font, fontSize: 26, fontWeight: 700, color: C.accentHi, marginBottom: 14, letterSpacing: "0.12em" }}>DEVICE DATA · JSON</div>
              {JSON_LINES.map(([k, v], i) => (
                <div
                  key={i}
                  style={{
                    fontFamily: C.mono,
                    fontSize: fs,
                    lineHeight: 1.5,
                    whiteSpace: "pre",
                    color: C.muted,
                    opacity: interpolate(frame, [flowAt - 8 + i * 3, flowAt - 2 + i * 3], [0, 1], clamp),
                  }}
                >
                  {k}
                  {v ? <span style={{ color: C.accentHi }}>{v}</span> : null}
                </div>
              ))}
            </Panel>
          </div>
        </div>
      }
    />
  );
};

/* ---------- Diff + SIEM ---------- */

const DIFF: Array<{ t: string; kind: " " | "-" | "+" }> = [
  { t: '"IPADDR": "10.20.1.15/24"', kind: " " },
  { t: '"TELNET": "DISABLED"', kind: "-" },
  { t: '"TELNET": "ENABLED"', kind: "+" },
  { t: '"51P1P": "6.00"', kind: "-" },
  { t: '"51P1P": "60.00"', kind: "+" },
  { t: '"SER": "ENABLED"', kind: " " },
];

export const DiffScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { pick } = useLayout();
  const cue = useCue();
  const hlAt = cue("diff", 0.25) + 10;
  const siemAt = cue("siem", 0.7);
  const fs = pick(34, 36);
  const badge = useEnter(hlAt + 8, { damping: 12, mass: 0.6 });
  return (
    <Feature
      icon={<GitCompareArrows size={40} color={C.accentHi} />}
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 32, width: "100%", maxWidth: 1060 }}>
          <Rise delay={12}>
            <Panel style={{ overflow: "hidden" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px 30px", borderBottom: `1px solid ${C.border}`, fontFamily: C.mono, fontSize: 24, color: C.dim }}>
                <span>golden/relay-451 ↔ pull/2026-10-17</span>
                <span
                  style={{
                    fontFamily: C.font,
                    fontWeight: 800,
                    fontSize: 26,
                    color: C.warn,
                    border: `2px solid ${C.warn}`,
                    borderRadius: 999,
                    padding: "4px 14px",
                    opacity: badge,
                    transform: `scale(${interpolate(badge, [0, 1], [0.6, 1])})`,
                  }}
                >
                  2 CHANGES
                </span>
              </div>
              <div style={{ padding: "16px 0" }}>
                {DIFF.map((d, i) => {
                  const o = interpolate(frame, [18 + i * 5, 24 + i * 5], [0, 1], clamp);
                  const hl = d.kind !== " " && frame > hlAt;
                  const color = d.kind === "+" ? C.ok : d.kind === "-" ? C.danger : C.muted;
                  return (
                    <div key={i} style={{ opacity: o, fontFamily: C.mono, fontSize: fs, lineHeight: 1.7, whiteSpace: "pre", padding: "0 26px", color: hl ? color : C.muted, background: hl ? alpha(color, 0.12) : "transparent" }}>
                      {d.kind} {d.t}
                    </div>
                  );
                })}
              </div>
            </Panel>
          </Rise>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", justifyContent: "center", alignItems: "center" }}>
            {["Elasticsearch", "Malcolm", "Splunk"].map((name, i) => (
              <Chip key={name} delay={siemAt + i * 10} size={pick(32, 34)} icon={<Database size={32} />}>
                {name}
              </Chip>
            ))}
          </div>
        </div>
      }
    />
  );
};

/* ---------- Free ---------- */

export const FreeScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { padding, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const zeroAt = cue("zero", 0.2);
  const strike = interpolate(frame, [zeroAt - 18, zeroAt - 4], [0, 1], clamp);
  const zero = spring({ frame: frame - zeroAt, fps, config: { damping: 10, mass: 0.8 } });
  const chipsAt = cue("chips", 0.55);
  const chips = copy.list("chips");
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: pick(20, 30) }}>
      <div style={{ position: "relative", fontFamily: C.font, fontWeight: C.headWeight, fontSize: pick(72, 64), color: C.dim, textAlign: "center" }}>
        {copy.str("struck")}
        <div style={{ position: "absolute", left: -10, top: "52%", height: 8, width: `calc(${strike * 100}% + 20px)`, background: C.danger, borderRadius: 4, transform: "rotate(-3deg)" }} />
      </div>
      <div
        style={{
          fontFamily: C.font,
          fontWeight: 800,
          fontSize: 300,
          lineHeight: 1,
          color: C.accentHi,
          letterSpacing: "-0.05em",
          opacity: Math.min(1, zero * 1.4),
          transform: `scale(${interpolate(zero, [0, 1], [0.4, 1])})`,
          textShadow: C.dark ? `0 0 80px ${alpha(C.accent, 0.66)}` : undefined,
        }}
      >
        {copy.str("big", "$0")}
      </div>
      <Words text={copy.str("line")} delay={zeroAt + 8} size={pick(64, 60)} align="center" />
      <div style={{ display: "flex", gap: 22, marginTop: 24, flexWrap: "wrap", justifyContent: "center" }}>
        {chips.map((c, i) => (
          <Chip key={c} delay={chipsAt + i * 16} size={36} icon={i === 0 ? <BookOpen size={36} /> : <FileCode2 size={36} />}>
            {c}
          </Chip>
        ))}
      </div>
    </AbsoluteFill>
  );
};

/* ---------- CTA ---------- */

export const CtaScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { isPortrait, padding, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const btnAt = cue("url", 0.6);
  // A long tagline gets a deliberate line break in landscape too.
  const twoLines = `${copy.str("line1")} ${copy.str("line2")}`.length > 32;
  const btn = spring({ frame: frame - btnAt, fps, config: { damping: 12, mass: 0.7 } });
  const glow = 0.6 + 0.4 * Math.sin(frame / 10);
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: pick(40, 56) }}>
      <Logo height={pick(280, 380)} delay={0} />
      {isPortrait && copy.list("portraitLines").length ? (
        <div>
          {copy.list("portraitLines").map((l, i) => (
            <Words key={i} text={l} delay={10 + i * 8} stagger={5} size={80} align="center" />
          ))}
        </div>
      ) : isPortrait || twoLines ? (
        <div>
          <Words text={copy.str("line1")} delay={10} stagger={5} size={pick(88, 100)} align="center" />
          <Words text={copy.str("line2")} delay={20} stagger={5} size={pick(88, 100)} align="center" />
        </div>
      ) : (
        <Words text={`${copy.str("line1")} ${copy.str("line2")}`} delay={10} stagger={5} size={96} align="center" />
      )}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 22,
          padding: pick("26px 52px", "26px 40px"),
          borderRadius: C.radius <= 6 ? C.radius : 999,
          background: C.accent,
          color: C.accentInk,
          fontFamily: C.font,
          fontWeight: 800,
          fontSize: pick(48, 44),
          opacity: Math.min(1, btn * 1.5),
          transform: `scale(${interpolate(btn, [0, 1], [0.7, 1])})`,
          boxShadow: `0 0 ${50 + 40 * glow}px ${alpha(C.accent, C.dark ? 0.6 : 0.3)}`,
        }}
      >
        <GitHubMark size={pick(52, 48)} color={C.accentInk} />
        github.com/sandialabs/PEAT
      </div>
      <Rise delay={btnAt + 20} y={16}>
        <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", alignItems: "center", gap: isPortrait ? 14 : 30, fontFamily: C.font, fontSize: 32, color: C.muted }}>
          <span style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <BookOpen size={32} color={C.accentHi} /> Docs: <span style={{ color: C.text, fontWeight: 600 }}>sandialabs.github.io/PEAT</span>
          </span>
          {isPortrait ? null : <span style={{ color: C.dim }}>·</span>}
          <span>Free & open source · GPL licensed</span>
        </div>
      </Rise>
    </AbsoluteFill>
  );
};
