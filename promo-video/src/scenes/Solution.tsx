import React from "react";
import { AbsoluteFill, Img, interpolate, random, spring, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import {
  ArrowDown,
  ArrowRight,
  BookOpen,
  Braces,
  Cable,
  CircleCheck,
  Container,
  Cpu,
  Database,
  FileCode2,
  GitCompareArrows,
  HardDrive,
  Monitor,
  ScrollText,
  SlidersHorizontal,
  Terminal as TerminalIcon,
} from "lucide-react";
import { C, FONT, MONO } from "../theme";
import { useLayout } from "../layout";
import { Chip, Eyebrow, Panel, Rise, Terminal, Words, useEnter } from "../components/ui";

// Cue frames below are word timings from the voiceover (scene start + LEAD + word time).

const GitHubMark: React.FC<{ size: number; color: string }> = ({ size, color }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill={color} aria-hidden>
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
  </svg>
);

const Logo: React.FC<{ height: number; delay?: number }> = ({ height, delay = 0 }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - delay, fps, config: { damping: 12, mass: 0.8 } });
  const ring = interpolate(frame - delay, [4, 40], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <div style={{ position: "relative", height, width: height * (843 / 900), display: "flex", justifyContent: "center", alignItems: "center" }}>
      <div
        style={{
          position: "absolute",
          width: height * 1.5,
          height: height * 1.5,
          borderRadius: "50%",
          border: `3px solid ${C.cyan}`,
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
          background: `radial-gradient(circle, ${C.cyan}40 0%, transparent 65%)`,
          opacity: p,
        }}
      />
      <Img
        src={staticFile("peat-logo.png")}
        style={{
          height,
          opacity: Math.min(1, p * 1.4),
          transform: `scale(${interpolate(p, [0, 1], [0.55, 1])})`,
          filter: `blur(${(1 - Math.min(1, p)) * 12}px) drop-shadow(0 0 40px ${C.cyan}55)`,
        }}
      />
    </div>
  );
};

/* ---------- 6. Reveal ---------- */

export const RevealScene: React.FC = () => {
  const { isPortrait, padding, pick } = useLayout();
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: pick(36, 56) }}>
      <Logo height={pick(400, 480)} delay={8} />
      <Words
        text="Process Extraction and Analysis Tool"
        delay={50}
        stagger={4}
        size={pick(76, 76)}
        align="center"
        style={{ maxWidth: isPortrait ? 900 : 1600 }}
      />
      <Rise delay={128} y={20}>
        <div style={{ fontFamily: FONT, fontSize: pick(36, 36), color: C.muted, textAlign: "center", fontWeight: 500 }}>
          Built at <span style={{ color: C.text, fontWeight: 700 }}>Sandia National Laboratories</span>
        </div>
      </Rise>
    </AbsoluteFill>
  );
};

/* ---------- shared feature layout ---------- */

const Feature: React.FC<{
  step: string;
  icon: React.ReactNode;
  title: string;
  sub: string;
  visual: React.ReactNode;
  textWidth?: number;
}> = ({ step, icon, title, sub, visual, textWidth = 600 }) => {
  const { isPortrait, padding, pick } = useLayout();
  return (
    <AbsoluteFill
      style={{
        padding,
        display: "flex",
        flexDirection: isPortrait ? "column" : "row",
        alignItems: "center",
        justifyContent: "center",
        gap: pick(80, 70),
      }}
    >
      <div style={{ width: isPortrait ? "100%" : textWidth, flexShrink: 0, display: "flex", flexDirection: "column", gap: 26 }}>
        <Rise delay={2} y={20}>
          <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
            <div
              style={{
                width: 76,
                height: 76,
                borderRadius: 20,
                background: `${C.cyan}22`,
                border: `2px solid ${C.cyan}88`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {icon}
            </div>
            <Eyebrow label={step} color={C.cyanBright} delay={4} size={30} />
          </div>
        </Rise>
        <Words text={title} delay={8} stagger={3} size={pick(76, 74)} accent={C.cyanBright} />
        <Rise delay={20} y={20}>
          <div style={{ fontFamily: FONT, fontSize: pick(34, 34), color: C.muted, lineHeight: 1.35 }}>{sub}</div>
        </Rise>
      </div>
      <div style={{ flex: isPortrait ? "none" : 1, width: isPortrait ? "100%" : undefined, display: "flex", justifyContent: "center" }}>
        {visual}
      </div>
    </AbsoluteFill>
  );
};

/* ---------- 7. Scan ---------- */

export const ScanScene: React.FC = () => {
  const { pick } = useLayout();
  const p = useEnter(4);
  const rows = [
    ["192.0.2.10", "SEL-451", "relay"],
    ["192.0.2.21", "Modicon M340", "PLC"],
    ["192.0.2.33", "ControlLogix", "PLC"],
    ["192.0.2.47", "Sage 3030M", "RTU"],
  ];
  const pad = (s: string, n: number) => s.padEnd(n, " ");
  return (
    <Feature
      step="01 · SCAN"
      icon={<TerminalIcon size={40} color={C.cyanBright} />}
      title="Find & *fingerprint* OT devices"
      sub="Discovers what's on the network and verifies vendor and model."
      visual={
        <div style={{ width: "100%", transform: `perspective(1400px) rotateY(${pick(-9, 0)}deg) rotateX(${pick(4, 6)}deg) scale(${0.92 + p * 0.08})`, opacity: p }}>
          <Terminal
            title="peat — scan"
            command="peat scan -i 192.0.2.0/24"
            commandAt={6}
            fontSize={pick(34, 32)}
            lines={[
              { text: "probing 254 hosts…", at: 30, color: C.dim },
              ...rows.map((r, i) => ({
                text: `${pad(r[0], 13)}${pad(r[1], 14)}${pad(r[2], 6)}✔`,
                at: 38 + i * 9,
                color: C.text,
              })),
              { text: "4 OT devices identified", at: 80, color: C.cyanBright, bold: true },
            ]}
          />
        </div>
      }
    />
  );
};

/* ---------- 8. Pull ---------- */

const ARTIFACTS = [
  { label: "Logic", detail: "ladder · ST · protection", Icon: FileCode2, at: 20 },
  { label: "Configs", detail: "IPs · services · users", Icon: SlidersHorizontal, at: 47 },
  { label: "Logs", detail: "SER · audit · events", Icon: ScrollText, at: 77 },
  { label: "Firmware", detail: "images · hashes", Icon: HardDrive, at: 105 },
];

export const PullScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { pick } = useLayout();
  return (
    <Feature
      step="02 · PULL"
      icon={<Cpu size={40} color={C.cyanBright} />}
      title="Collect the *artifacts* that matter"
      sub="Deep, read-focused collection from live devices."
      textWidth={500}
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 30, width: "100%", maxWidth: 1060 }}>
          <div style={{ display: "grid", gridTemplateColumns: pick("1fr 1fr", "1fr"), gap: 26 }}>
            {ARTIFACTS.map(({ label, detail, Icon, at }) => {
              const p = spring({ frame: frame - at, fps, config: { damping: 13, mass: 0.7 } });
              const done = frame > at + 16;
              return (
                <div
                  key={label}
                  style={{
                    opacity: Math.min(1, p * 1.4),
                    transform: `translateY(${(1 - p) * 60}px) scale(${interpolate(p, [0, 1], [0.8, 1])})`,
                  }}
                >
                  <Panel glow={done ? C.cyan : undefined} style={{ padding: pick("40px 34px", "34px 36px"), display: "flex", alignItems: "center", gap: 26 }}>
                    <Icon size={pick(72, 72)} color={C.cyanBright} strokeWidth={1.6} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontFamily: FONT, fontWeight: 800, fontSize: pick(50, 52), color: C.text }}>{label}</div>
                      <div style={{ fontFamily: FONT, fontSize: pick(28, 30), color: C.muted }}>{detail}</div>
                    </div>
                    <CircleCheck size={46} color={C.green} style={{ opacity: done ? 1 : 0.15 }} />
                  </Panel>
                </div>
              );
            })}
          </div>
          <div style={{ display: "flex", gap: 20, justifyContent: "center" }}>
            <Chip color={C.cyanBright} delay={146} size={pick(34, 36)} icon={<Cable size={36} />}>
              Ethernet
            </Chip>
            <Chip color={C.cyanBright} delay={170} size={pick(34, 36)} icon={<Cable size={36} />}>
              Serial (RS-232)
            </Chip>
          </div>
        </div>
      }
    />
  );
};

/* ---------- 9. Parse ---------- */

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
  const frame = useCurrentFrame();
  const { isPortrait, pick } = useLayout();
  const flow = interpolate(frame, [40, 66], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const fs = pick(25, 32);
  const Arrow = isPortrait ? ArrowDown : ArrowRight;
  return (
    <Feature
      step="03 · PARSE"
      icon={<Braces size={40} color={C.cyanBright} />}
      title="One *data model.* Every vendor."
      sub="Proprietary formats decoded into standardized, human-readable JSON."
      textWidth={460}
      visual={
        <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", alignItems: "center", gap: 22, width: "100%" }}>
          <Rise delay={14} style={{ flex: 1, width: isPortrait ? "100%" : undefined }}>
            <Panel style={{ padding: 32 }}>
              <div style={{ fontFamily: FONT, fontSize: 26, fontWeight: 700, color: C.amber, marginBottom: 14, letterSpacing: "0.12em" }}>
                PROPRIETARY BLOB
              </div>
              {HEX.slice(0, isPortrait ? 5 : 7).map((row, i) => (
                <div key={i} style={{ fontFamily: MONO, fontSize: fs, color: C.dim, lineHeight: 1.6, whiteSpace: "pre", opacity: 1 - flow * 0.5 }}>
                  {row}
                </div>
              ))}
              <div style={{ fontFamily: MONO, fontSize: 24, color: C.muted, marginTop: 12 }}>.l5x · .rdb · SET_ALL.TXT · UMAS</div>
            </Panel>
          </Rise>
          <Arrow size={64} color={C.cyanBright} style={{ opacity: flow, flexShrink: 0, filter: `drop-shadow(0 0 12px ${C.cyan})` }} />
          <div style={{ flex: 1.25, width: isPortrait ? "100%" : undefined, opacity: flow, transform: `translateX(${(1 - flow) * 40}px)` }}>
            <Panel glow={C.cyan} style={{ padding: 32 }}>
              <div style={{ fontFamily: FONT, fontSize: 26, fontWeight: 700, color: C.cyanBright, marginBottom: 14, letterSpacing: "0.12em" }}>
                DEVICE DATA · JSON
              </div>
              {JSON_LINES.map(([k, v], i) => (
                <div
                  key={i}
                  style={{
                    fontFamily: MONO,
                    fontSize: fs,
                    lineHeight: 1.5,
                    whiteSpace: "pre",
                    color: C.muted,
                    opacity: interpolate(frame, [52 + i * 3, 58 + i * 3], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
                  }}
                >
                  {k}
                  {v ? <span style={{ color: C.cyanBright }}>{v}</span> : null}
                </div>
              ))}
            </Panel>
          </div>
        </div>
      }
    />
  );
};

/* ---------- 10. Diff + SIEM ---------- */

const DIFF: Array<{ t: string; kind: " " | "-" | "+" }> = [
  { t: '"IPADDR": "10.20.1.15/24"', kind: " " },
  { t: '"TELNET": "DISABLED"', kind: "-" },
  { t: '"TELNET": "ENABLED"', kind: "+" },
  { t: '"51P1P": "6.00"', kind: "-" },
  { t: '"51P1P": "60.00"', kind: "+" },
  { t: '"SER": "ENABLED"', kind: " " },
];

export const DiffScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { pick } = useLayout();
  const fs = pick(34, 36);
  const badge = useEnter(60, { damping: 12, mass: 0.6 });
  return (
    <Feature
      step="04 · DIFF & SHIP"
      icon={<GitCompareArrows size={40} color={C.cyanBright} />}
      title="Catch *every change*"
      sub="Compare against your golden config, then send results to your SIEM."
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 32, width: "100%", maxWidth: 1060 }}>
          <Rise delay={12}>
            <Panel style={{ overflow: "hidden" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px 30px", borderBottom: `1px solid ${C.border}`, fontFamily: MONO, fontSize: pick(24, 24), color: C.dim }}>
                <span>golden/relay-451 ↔ pull/2026-10-17</span>
                <span
                  style={{
                    fontFamily: FONT,
                    fontWeight: 800,
                    fontSize: 26,
                    color: C.amber,
                    border: `2px solid ${C.amber}`,
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
                  const o = interpolate(frame, [18 + i * 5, 24 + i * 5], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
                  const hl = d.kind !== " " && frame > 44;
                  const color = d.kind === "+" ? C.green : d.kind === "-" ? C.red : C.muted;
                  return (
                    <div
                      key={i}
                      style={{
                        opacity: o,
                        fontFamily: MONO,
                        fontSize: fs,
                        lineHeight: 1.7,
                        whiteSpace: "pre",
                        padding: "0 26px",
                        color: hl ? color : C.muted,
                        background: hl ? `${color}1F` : "transparent",
                      }}
                    >
                      {d.kind} {d.t}
                    </div>
                  );
                })}
              </div>
            </Panel>
          </Rise>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", justifyContent: "center", alignItems: "center" }}>
            <Chip color={C.cyanBright} delay={100} size={pick(32, 34)} icon={<Database size={32} />}>
              Elasticsearch
            </Chip>
            <Chip color={C.cyanBright} delay={110} size={pick(32, 34)} icon={<Database size={32} />}>
              Malcolm
            </Chip>
            <Chip color={C.cyanBright} delay={124} size={pick(32, 34)} icon={<Database size={32} />}>
              Splunk
            </Chip>
          </div>
        </div>
      }
    />
  );
};

/* ---------- 11. Proof ---------- */

const Stat: React.FC<{ value: number; suffix?: string; label: string; delay: number; size: number }> = ({ value, suffix = "", label, delay, size }) => {
  const frame = useCurrentFrame();
  const p = useEnter(delay, { damping: 14 });
  const n = Math.round(interpolate(frame, [delay, delay + 22], [0, value], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }));
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", opacity: Math.min(1, p * 1.4), transform: `scale(${interpolate(p, [0, 1], [0.7, 1])})` }}>
      <div style={{ fontFamily: FONT, fontWeight: 800, fontSize: size, color: C.cyanBright, textShadow: `0 0 40px ${C.cyan}66`, fontVariantNumeric: "tabular-nums", letterSpacing: "-0.03em" }}>
        {n}
        {suffix}
      </div>
      <div style={{ fontFamily: FONT, fontSize: size * 0.27, color: C.muted, fontWeight: 600 }}>{label}</div>
    </div>
  );
};

export const ProofScene: React.FC = () => {
  const { isPortrait, padding, pick } = useLayout();
  const platforms = [
    { name: "Linux", Icon: TerminalIcon, at: 54 },
    { name: "Windows", Icon: Monitor, at: 75 },
    { name: "Docker", Icon: Container, at: 88 },
  ];
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", gap: pick(70, 90) }}>
      <Eyebrow label="PROVEN IN YEARS OF EXERCISES & ASSESSMENTS" color={C.cyanBright} delay={2} size={pick(26, 22)} center />
      <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", gap: pick(140, 60), alignItems: "center" }}>
        <Stat value={10} suffix="+" label="vendors" delay={8} size={pick(170, 160)} />
        <Stat value={25} suffix="+" label="device families" delay={20} size={pick(170, 160)} />
        <Stat value={13} label="protocols" delay={32} size={pick(170, 160)} />
      </div>
      <div style={{ display: "flex", gap: 24, flexWrap: "wrap", justifyContent: "center" }}>
        {platforms.map(({ name, Icon, at }) => (
          <Chip key={name} color={C.text} delay={at} size={pick(40, 38)} icon={<Icon size={40} />}>
            {name}
          </Chip>
        ))}
      </div>
    </AbsoluteFill>
  );
};

/* ---------- 12. Free ---------- */

export const FreeScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { padding, pick } = useLayout();
  const strike = interpolate(frame, [8, 22], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const zero = spring({ frame: frame - 22, fps, config: { damping: 10, mass: 0.8 } });
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: pick(20, 30) }}>
      <div style={{ position: "relative", fontFamily: FONT, fontWeight: 800, fontSize: pick(80, 76), color: C.dim }}>
        $11,000 / seat
        <div style={{ position: "absolute", left: -10, top: "52%", height: 8, width: `calc(${strike * 100}% + 20px)`, background: C.red, borderRadius: 4, transform: "rotate(-4deg)" }} />
      </div>
      <div
        style={{
          fontFamily: FONT,
          fontWeight: 800,
          fontSize: pick(300, 300),
          lineHeight: 1,
          color: C.cyanBright,
          letterSpacing: "-0.05em",
          opacity: Math.min(1, zero * 1.4),
          transform: `scale(${interpolate(zero, [0, 1], [0.4, 1])})`,
          textShadow: `0 0 80px ${C.cyan}AA`,
        }}
      >
        $0
      </div>
      <Words text="No license fees. *Free to use.*" delay={30} size={pick(64, 60)} align="center" accent={C.cyanBright} />
      <div style={{ display: "flex", gap: 22, marginTop: 24, flexWrap: "wrap", justifyContent: "center" }}>
        <Chip color={C.cyanBright} delay={56} size={36} icon={<BookOpen size={36} />}>
          Open source
        </Chip>
        <Chip color={C.cyanBright} delay={100} size={36} icon={<FileCode2 size={36} />}>
          GPLv3
        </Chip>
      </div>
    </AbsoluteFill>
  );
};

/* ---------- 13. CTA ---------- */

export const CtaScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { isPortrait, padding, pick } = useLayout();
  const btn = spring({ frame: frame - 84, fps, config: { damping: 12, mass: 0.7 } });
  const glow = 0.6 + 0.4 * Math.sin(frame / 10);
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: pick(40, 56) }}>
      <Logo height={pick(280, 380)} delay={0} />
      {isPortrait ? (
        <div>
          <Words text="Close the" delay={10} stagger={5} size={104} align="center" />
          <Words text="*visibility gap.*" delay={20} stagger={5} size={104} align="center" accent={C.cyanBright} />
        </div>
      ) : (
        <Words text="Close the *visibility gap.*" delay={10} stagger={5} size={100} align="center" accent={C.cyanBright} />
      )}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 22,
          padding: pick("26px 52px", "26px 40px"),
          borderRadius: 999,
          background: C.cyan,
          color: "#03121A",
          fontFamily: FONT,
          fontWeight: 800,
          fontSize: pick(48, 44),
          opacity: Math.min(1, btn * 1.5),
          transform: `scale(${interpolate(btn, [0, 1], [0.7, 1])})`,
          boxShadow: `0 0 ${50 + 40 * glow}px ${C.cyan}99`,
        }}
      >
        <GitHubMark size={pick(52, 48)} color="#03121A" />
        github.com/sandialabs/PEAT
      </div>
      <Rise delay={104} y={16}>
        <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", alignItems: "center", gap: isPortrait ? 14 : 30, fontFamily: FONT, fontSize: pick(32, 32), color: C.muted }}>
          <span style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <BookOpen size={32} color={C.cyanBright} /> Docs: <span style={{ color: C.text, fontWeight: 600 }}>sandialabs.github.io/PEAT</span>
          </span>
          {isPortrait ? null : <span style={{ color: C.dim }}>·</span>}
          <span>Free & open source · GPLv3</span>
        </div>
      </Rise>
    </AbsoluteFill>
  );
};
