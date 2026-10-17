import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import {
  Boxes,
  CircleCheck,
  Code,
  Container,
  Cpu,
  Download,
  FilePlus2,
  Filter,
  Fingerprint,
  Folder,
  Gauge,
  Laptop,
  ListOrdered,
  Monitor,
  Router,
  Shield,
  ShieldCheck,
  Terminal as TerminalIcon,
  Zap,
} from "lucide-react";
import { alpha, useTheme } from "../theme";
import { useLayout } from "../layout";
import { useCopy, useCue } from "../timeline";
import { Chip, clamp, Eyebrow, Panel, Rise, Stage, Words } from "../components/ui";
import { PlcRack } from "../components/Hardware";
import { Feature } from "./Solution";

/* ---------- Safety ---------- */

const SAFETY_ICONS = [ShieldCheck, ListOrdered, Fingerprint, Filter];

/** A calm process trend: it stays steady while PEAT collects. */
const Heartbeat: React.FC<{ width: number; height: number }> = ({ width, height }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const points = Array.from({ length: 80 }, (_, i) => {
    const x = (i / 79) * width;
    const y = height / 2 + Math.sin((i + frame * 0.6) / 6) * height * 0.12 + Math.sin((i + frame) / 2.3) * height * 0.03;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  return (
    <svg width={width} height={height}>
      <line x1="0" y1={height * 0.22} x2={width} y2={height * 0.22} stroke={alpha(C.warn, 0.5)} strokeDasharray="8 8" strokeWidth="2" />
      <line x1="0" y1={height * 0.78} x2={width} y2={height * 0.78} stroke={alpha(C.warn, 0.5)} strokeDasharray="8 8" strokeWidth="2" />
      <polyline points={points} fill="none" stroke={C.ok} strokeWidth="4" strokeLinejoin="round" />
    </svg>
  );
};

export const SafetyScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { isPortrait, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const items = copy.list("items");
  const fractions = [0.3, 0.5, 0.65, 0.8];

  const list = (
    <div style={{ display: "flex", flexDirection: "column", gap: pick(22, 20), flex: 1 }}>
      {items.map((item, i) => {
        const at = cue(`i${i + 1}`, fractions[i]);
        const p = spring({ frame: frame - at, fps, config: { damping: 14, mass: 0.6 } });
        const Icon = SAFETY_ICONS[i % SAFETY_ICONS.length];
        return (
          <div key={item} style={{ opacity: Math.min(1, p * 1.4), transform: `translateX(${(1 - p) * -50}px)` }}>
            <Panel glow={p > 0.9 ? C.ok : undefined} style={{ padding: pick("24px 30px", "24px 26px"), display: "flex", alignItems: "center", gap: 24 }}>
              <Icon size={pick(52, 50)} color={C.ok} strokeWidth={1.7} />
              <div style={{ fontFamily: C.font, fontWeight: 700, fontSize: pick(38, 36), color: C.text }}>{item}</div>
            </Panel>
          </div>
        );
      })}
    </div>
  );

  const device = (
    <Rise delay={10} style={{ flexShrink: 0 }}>
      <Panel style={{ padding: 30, display: "flex", flexDirection: "column", alignItems: "center", gap: 18 }}>
        <PlcRack width={pick(520, 760)} />
        <Heartbeat width={pick(520, 760)} height={110} />
        <div style={{ display: "flex", alignItems: "center", gap: 14, fontFamily: C.mono, fontSize: pick(28, 28), color: C.ok }}>
          <CircleCheck size={30} /> {copy.str("status")}
        </div>
      </Panel>
    </Rise>
  );

  return (
    <Stage gap={pick(44, 52)}>
      <Eyebrow label={copy.str("eyebrow")} color={C.ok} delay={2} />
      <Words text={copy.str("headline")} delay={6} size={pick(84, 76)} accent={C.ok} />
      <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", gap: pick(50, 40), alignItems: isPortrait ? "stretch" : "center" }}>
        {isPortrait ? device : null}
        {list}
        {isPortrait ? null : device}
      </div>
    </Stage>
  );
};

/* ---------- Devices: what PEAT collects from ---------- */

const DEVICE_TYPES = [
  { label: "PLCs", Icon: Cpu, cue: "plcs", f: 0.25 },
  { label: "Protection relays", Icon: Zap, cue: "relays", f: 0.4 },
  { label: "RTUs & RTACs", Icon: Router, cue: "rtus", f: 0.55 },
  { label: "Generator controls", Icon: Gauge, cue: "more", f: 0.65 },
  { label: "HMIs", Icon: Monitor, cue: "more", f: 0.65 },
  { label: "Gateways & modems", Icon: Shield, cue: "more", f: 0.65 },
];

// Vendors with integrated PEAT modules (docs/supported_devices.csv, plus OpenPLC).
const VENDORS = ["SEL", "Rockwell", "Schneider Electric", "Siemens", "GE", "Woodward", "Camlin", "iDirect", "Fortinet", "OpenPLC"];

export const DevicesScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { isPortrait, padding, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const vendorsAt = cue("vendors", 0.9);
  const lit = interpolate(frame, [vendorsAt - 4, vendorsAt + 10], [0, 1], clamp);
  let moreIndex = 0;
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", justifyContent: "center", gap: pick(40, 48) }}>
      <Eyebrow label={copy.str("eyebrow")} color={C.warn} delay={2} size={pick(28, 26)} />
      <Words text={copy.str("headline")} delay={8} size={pick(84, 78)} accent={C.warn} />
      <div style={{ display: "flex", flexWrap: "wrap", gap: pick(18, 16) }}>
        {DEVICE_TYPES.map(({ label, Icon, cue: c, f }) => {
          const extra = c === "more" ? moreIndex++ * 6 : 0;
          return (
            <Chip key={label} color={C.warn} delay={cue(c, f) + extra} size={32} icon={<Icon size={32} />}>
              {label}
            </Chip>
          );
        })}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: pick("repeat(5, 1fr)", "repeat(2, 1fr)"), gap: pick(18, 16) }}>
        {VENDORS.map((v, i) => {
          const p = spring({ frame: frame - 24 - i * 5, fps, config: { damping: 200 } });
          return (
            <div
              key={v}
              style={{
                opacity: p * interpolate(lit, [0, 1], [0.55, 1]),
                transform: `translateY(${(1 - p) * 24}px)`,
                height: pick(96, 92),
                borderRadius: Math.min(C.radius, 16),
                border: `2px solid ${lit > 0 ? alpha(C.warn, 0.25 + lit * 0.45) : C.border}`,
                background: alpha(C.warn, 0.03 + lit * 0.07),
                boxShadow: lit > 0 && C.dark ? `0 0 ${30 * lit}px ${alpha(C.warn, 0.25)}` : undefined,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: C.font,
                fontWeight: 700,
                fontSize: pick(v.length > 12 ? 28 : 34, v.length > 12 ? 30 : 36),
                color: C.text,
                textAlign: "center",
              }}
            >
              {v}
            </div>
          );
        })}
      </div>
      <Rise delay={vendorsAt + 10} y={16}>
        <div style={{ fontFamily: C.mono, fontSize: pick(30, 28), color: C.muted, textAlign: isPortrait ? "center" : "left" }}>{copy.str("footer")}</div>
      </Rise>
    </AbsoluteFill>
  );
};

/* ---------- Platforms: where PEAT itself runs ---------- */

const PLATFORMS = [
  { name: "Linux", Icon: TerminalIcon, cue: "linux", f: 0.2 },
  { name: "Windows", Icon: Monitor, cue: "windows", f: 0.3 },
  { name: "macOS", Icon: Laptop, cue: "macos", f: 0.42 },
  { name: "Docker", Icon: Container, cue: "docker", f: 0.52 },
];

export const PlatformsScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { padding, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const badgesAt = cue("badges", 0.75);
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", gap: pick(56, 64) }}>
      <Eyebrow label={copy.str("eyebrow")} delay={2} size={pick(28, 26)} center />
      <Words text={copy.str("headline")} delay={6} size={pick(96, 88)} align="center" />
      <div style={{ display: "grid", gridTemplateColumns: pick("repeat(4, 1fr)", "repeat(2, 1fr)"), gap: pick(32, 28), width: "100%", maxWidth: 1500 }}>
        {PLATFORMS.map(({ name, Icon, cue: c, f }) => {
          const p = spring({ frame: frame - cue(c, f), fps, config: { damping: 12, mass: 0.7 } });
          return (
            <div key={name} style={{ opacity: Math.min(1, p * 1.4), transform: `translateY(${(1 - p) * 60}px) scale(${interpolate(p, [0, 1], [0.8, 1])})` }}>
              <Panel glow={C.accent} style={{ padding: pick("44px 20px", "40px 16px"), display: "flex", flexDirection: "column", alignItems: "center", gap: 20 }}>
                <Icon size={96} color={C.accentHi} strokeWidth={1.4} />
                <div style={{ fontFamily: C.font, fontWeight: C.headWeight, fontSize: 48, color: C.text }}>{name}</div>
              </Panel>
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap", justifyContent: "center" }}>
        {copy.list("badges").map((b, i) => (
          <Chip key={b} color={C.ok} delay={badgesAt + i * 10} size={pick(34, 32)} icon={i === 0 ? <Download size={34} /> : <CircleCheck size={34} />}>
            {b}
          </Chip>
        ))}
      </div>
    </AbsoluteFill>
  );
};

/* ---------- Library: PEAT as a Python API ---------- */

export const LibraryScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const codeAt = cue("code", 0.25);
  const chipsAt = cue("chips", 0.7);
  const fs = pick(34, 30);
  // Mirrors the "Pull from a M340 PLC" example in docs/python_examples.rst.
  const code: Array<Array<[string, string]>> = [
    [["from ", C.dangerHi], ["peat ", C.text], ["import ", C.dangerHi], ["M340, datastore", C.text]],
    [],
    [["dev ", C.text], ["= ", C.muted], ["datastore.get(", C.text], ['"192.0.2.21"', C.warn], [")", C.text]],
    [["M340.pull(dev)", C.accentHi]],
    [["data ", C.text], ["= ", C.muted], ["dev.export()", C.accentHi]],
  ];
  return (
    <Feature
      icon={<Code size={40} color={C.accentHi} />}
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 28, width: "100%", maxWidth: 1000 }}>
          <Rise delay={8}>
            <Panel glow={C.accent} style={{ overflow: "hidden" }}>
              <div style={{ padding: "16px 26px", borderBottom: `1px solid ${C.border}`, fontFamily: C.mono, fontSize: 24, color: C.dim }}>my_assessment.py</div>
              <div style={{ padding: "26px 30px" }}>
                {code.map((tokens, i) => {
                  const o = interpolate(frame, [codeAt + i * 10, codeAt + 8 + i * 10], [0, 1], clamp);
                  return (
                    <div key={i} style={{ display: "flex", alignItems: "baseline", opacity: o, transform: `translateX(${(1 - o) * -14}px)`, fontFamily: C.mono, fontSize: fs, lineHeight: 1.7, minHeight: fs * 1.7, whiteSpace: "pre" }}>
                      <span style={{ width: fs * 1.6, color: C.dim, fontSize: fs * 0.75 }}>{i + 1}</span>
                      {tokens.map(([t, c], j) => (
                        <span key={j} style={{ color: c }}>
                          {t}
                        </span>
                      ))}
                    </div>
                  );
                })}
              </div>
            </Panel>
          </Rise>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap", justifyContent: "center" }}>
            {copy.list("chips").map((t, i) => (
              <Chip key={t} delay={chipsAt + i * 8} size={pick(32, 30)}>
                {t}
              </Chip>
            ))}
          </div>
        </div>
      }
    />
  );
};

/* ---------- Modules: easily extensible ---------- */

const TREE = ["sel/", "rockwell/", "schneider/", "siemens/", "ge/", "woodward/", "openplc/"];

export const ModulesScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { pick } = useLayout();
  const cue = useCue();
  const addAt = cue("add", 0.45);
  const codeAt = cue("code", 0.7);
  const fs = pick(26, 26);
  const added = spring({ frame: frame - addAt, fps, config: { damping: 12, mass: 0.6 } });
  const code: Array<Array<[string, string]>> = [
    [["class ", C.dangerHi], ["AwesomeTool", C.accentHi], ["(DeviceModule):", C.text]],
    [["    device_type ", C.text], ["= ", C.muted], ['"PLC"', C.warn]],
    [["    vendor_id ", C.text], ["= ", C.muted], ['"ACME"', C.warn]],
    [],
    [["    def ", C.dangerHi], ["_parse", C.accentHi], ["(cls, file, dev):", C.text]],
    [["        ...", C.dim]],
  ];
  return (
    <Feature
      icon={<Boxes size={40} color={C.accentHi} />}
      textWidth={520}
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 22, width: "100%", maxWidth: 1000 }}>
          <Rise delay={6}>
            <Panel style={{ padding: "24px 28px" }}>
              <div style={{ fontFamily: C.mono, fontSize: fs, color: C.muted, marginBottom: 8, display: "flex", alignItems: "center", gap: 12 }}>
                <Folder size={fs} color={C.accentHi} /> peat/modules/
              </div>
              <div style={{ display: "grid", gridTemplateColumns: pick("repeat(4, 1fr)", "1fr 1fr"), columnGap: 20 }}>
                {TREE.map((d, i) => {
                  const o = interpolate(frame, [14 + i * 5, 20 + i * 5], [0, 1], clamp);
                  const glow = interpolate(frame, [36 + i * 3, 42 + i * 3, 52 + i * 3], [0, 1, 0], clamp);
                  return (
                    <div key={d} style={{ opacity: o, fontFamily: C.mono, fontSize: fs, lineHeight: 1.6, color: glow > 0.1 ? C.accentHi : C.text, display: "flex", alignItems: "center", gap: 12, paddingLeft: 26 }}>
                      <Boxes size={fs * 0.9} color={C.dim} /> {d}
                    </div>
                  );
                })}
              </div>
              <div
                style={{
                  marginTop: 10,
                  marginLeft: 14,
                  padding: "6px 12px",
                  borderRadius: Math.min(C.radius, 10),
                  border: `2px solid ${C.ok}`,
                  background: alpha(C.ok, 0.1),
                  fontFamily: C.mono,
                  fontSize: fs,
                  color: C.ok,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 12,
                  opacity: Math.min(1, added * 1.4),
                  transform: `scale(${interpolate(added, [0, 1], [0.7, 1])})`,
                }}
              >
                <FilePlus2 size={fs} /> awesome_module.py
              </div>
            </Panel>
          </Rise>
          <Rise delay={codeAt}>
            <Panel glow={C.accent} style={{ padding: "24px 28px" }}>
              {code.map((tokens, i) => (
                <div key={i} style={{ fontFamily: C.mono, fontSize: fs, lineHeight: 1.6, minHeight: fs * 1.6, whiteSpace: "pre", opacity: interpolate(frame, [codeAt + 6 + i * 5, codeAt + 12 + i * 5], [0, 1], clamp) }}>
                  {tokens.map(([t, c], j) => (
                    <span key={j} style={{ color: c }}>
                      {t}
                    </span>
                  ))}
                </div>
              ))}
            </Panel>
          </Rise>
          <Rise delay={codeAt + 40} y={16}>
            <div style={{ fontFamily: C.mono, fontSize: pick(24, 21), color: C.text, background: C.subtle, border: `1px solid ${C.border}`, borderRadius: Math.min(C.radius, 12), padding: "12px 18px", whiteSpace: "pre" }}>
              <span style={{ color: C.accentHi }}>$ </span>peat parse -d AwesomeTool -I awesome_module.py -- out.json
            </div>
          </Rise>
        </div>
      }
    />
  );
};
