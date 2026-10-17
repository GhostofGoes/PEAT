import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import {
  Boxes,
  CircleCheck,
  Code,
  Container,
  Cpu,
  FilePlus2,
  Folder,
  Gauge,
  Laptop,
  Monitor,
  Router,
  Shield,
  Terminal as TerminalIcon,
  Zap,
} from "lucide-react";
import { C, FONT, MONO } from "../theme";
import { useLayout } from "../layout";
import { Chip, Eyebrow, Panel, Rise, Words } from "../components/ui";
import { Feature } from "./Solution";

// Scenes used only in the long cut. Cue frames are word timings from the voiceover
// (scene start + LEAD + word time).

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

/* ---------- Devices: what PEAT collects from ---------- */

const DEVICE_TYPES = [
  { label: "PLCs", Icon: Cpu, at: 74 },
  { label: "Protection relays", Icon: Zap, at: 116 },
  { label: "RTUs & RTACs", Icon: Router, at: 152 },
  { label: "Generator controls", Icon: Gauge, at: 178 },
  { label: "HMIs", Icon: Monitor, at: 184 },
  { label: "Gateways & modems", Icon: Shield, at: 190 },
];

// Vendors with integrated PEAT modules (docs/supported_devices.csv, plus OpenPLC).
const VENDORS = ["SEL", "Rockwell", "Schneider Electric", "Siemens", "GE", "Woodward", "Camlin", "iDirect", "Fortinet", "OpenPLC"];

export const DevicesScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { isPortrait, padding, pick } = useLayout();
  const lit = interpolate(frame, [218, 232], [0, 1], clamp);
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", justifyContent: "center", gap: pick(40, 48) }}>
      <Eyebrow label="WHAT PEAT COLLECTS FROM" color={C.amber} delay={2} size={pick(28, 26)} />
      <Words text="OT devices from *10+ vendors*" delay={8} size={pick(84, 80)} accent={C.amber} />
      <div style={{ display: "flex", flexWrap: "wrap", gap: pick(18, 16) }}>
        {DEVICE_TYPES.map(({ label, Icon, at }) => (
          <Chip key={label} color={C.amber} delay={at} size={pick(32, 32)} icon={<Icon size={32} />}>
            {label}
          </Chip>
        ))}
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
                borderRadius: 16,
                border: `2px solid ${lit > 0 ? `rgba(245,158,11,${0.25 + lit * 0.45})` : C.border}`,
                background: `rgba(245,158,11,${0.03 + lit * 0.07})`,
                boxShadow: lit > 0 ? `0 0 ${30 * lit}px rgba(245,158,11,0.25)` : undefined,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: FONT,
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
      <Rise delay={232} y={16}>
        <div style={{ fontFamily: MONO, fontSize: pick(30, 28), color: C.muted, textAlign: isPortrait ? "center" : "left" }}>
          25+ device families · 13 protocols · Ethernet & serial · project files too
        </div>
      </Rise>
    </AbsoluteFill>
  );
};

/* ---------- Platforms: where PEAT itself runs ---------- */

const PLATFORMS = [
  { name: "Linux", Icon: TerminalIcon, at: 38 },
  { name: "Windows", Icon: Monitor, at: 57 },
  { name: "macOS", Icon: Laptop, at: 81 },
  { name: "Docker", Icon: Container, at: 104 },
];

export const PlatformsScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { padding, pick } = useLayout();
  return (
    <AbsoluteFill style={{ padding, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", gap: pick(56, 64) }}>
      <Eyebrow label="WHERE PEAT RUNS" color={C.cyanBright} delay={2} size={pick(28, 26)} center />
      <Words text="Runs on *your* machine" delay={6} size={pick(96, 88)} align="center" />
      <div style={{ display: "grid", gridTemplateColumns: pick("repeat(4, 1fr)", "repeat(2, 1fr)"), gap: pick(32, 28), width: "100%", maxWidth: 1500 }}>
        {PLATFORMS.map(({ name, Icon, at }) => {
          const p = spring({ frame: frame - at, fps, config: { damping: 12, mass: 0.7 } });
          return (
            <div key={name} style={{ opacity: Math.min(1, p * 1.4), transform: `translateY(${(1 - p) * 60}px) scale(${interpolate(p, [0, 1], [0.8, 1])})` }}>
              <Panel glow={C.cyan} style={{ padding: pick("44px 20px", "40px 16px"), display: "flex", flexDirection: "column", alignItems: "center", gap: 20 }}>
                <Icon size={pick(96, 96)} color={C.cyanBright} strokeWidth={1.4} />
                <div style={{ fontFamily: FONT, fontWeight: 800, fontSize: pick(48, 48), color: C.text }}>{name}</div>
              </Panel>
            </div>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap", justifyContent: "center" }}>
        <Chip color={C.green} delay={136} size={pick(34, 32)} icon={<CircleCheck size={34} />}>
          No Python install needed
        </Chip>
        <Chip color={C.green} delay={146} size={pick(34, 32)} icon={<CircleCheck size={34} />}>
          No vendor software
        </Chip>
      </div>
    </AbsoluteFill>
  );
};

/* ---------- Library: PEAT as a Python API ---------- */

// Mirrors the "Pull from a M340 PLC" example in docs/python_examples.rst.
const CODE: Array<Array<[string, string]>> = [
  [["from ", C.redSoft], ["peat ", C.text], ["import ", C.redSoft], ["M340, datastore", C.text]],
  [],
  [["dev ", C.text], ["= ", C.muted], ["datastore.get(", C.text], ['"192.0.2.21"', C.amber], [")", C.text]],
  [["M340.pull(dev)", C.cyanBright]],
  [["data ", C.text], ["= ", C.muted], ["dev.export()", C.cyanBright]],
];

export const LibraryScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { pick } = useLayout();
  const fs = pick(34, 30);
  return (
    <Feature
      step="PYTHON API"
      icon={<Code size={40} color={C.cyanBright} />}
      title="Use it as a *Python library*"
      sub="Script pulls, parsing and analysis into your own tools."
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 28, width: "100%", maxWidth: 1000 }}>
          <Rise delay={8}>
            <Panel glow={C.cyan} style={{ overflow: "hidden" }}>
              <div style={{ padding: "16px 26px", borderBottom: `1px solid ${C.border}`, fontFamily: MONO, fontSize: 24, color: C.dim }}>my_assessment.py</div>
              <div style={{ padding: "26px 30px" }}>
                {CODE.map((tokens, i) => {
                  const o = interpolate(frame, [40 + i * 10, 48 + i * 10], [0, 1], clamp);
                  return (
                    <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 0, opacity: o, transform: `translateX(${(1 - o) * -14}px)`, fontFamily: MONO, fontSize: fs, lineHeight: 1.7, minHeight: fs * 1.7, whiteSpace: "pre" }}>
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
            {["Scheduled pulls", "Pipelines", "Analytics"].map((t, i) => (
              <Chip key={t} color={C.cyanBright} delay={138 + i * 8} size={pick(32, 30)}>
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
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { pick } = useLayout();
  const fs = pick(26, 26);
  const added = spring({ frame: frame - 88, fps, config: { damping: 12, mass: 0.6 } });
  const tree = (
    <Rise delay={6}>
      <Panel style={{ padding: "24px 28px" }}>
        <div style={{ fontFamily: MONO, fontSize: fs, color: C.muted, marginBottom: 8, display: "flex", alignItems: "center", gap: 12 }}>
          <Folder size={fs} color={C.cyanBright} /> peat/modules/
        </div>
        <div style={{ display: "grid", gridTemplateColumns: pick("repeat(4, 1fr)", "1fr 1fr"), columnGap: 20 }}>
          {TREE.map((d, i) => {
            const o = interpolate(frame, [14 + i * 5, 20 + i * 5], [0, 1], clamp);
            const glow = interpolate(frame, [36 + i * 3, 42 + i * 3, 52 + i * 3], [0, 1, 0], clamp);
            return (
              <div key={d} style={{ opacity: o, fontFamily: MONO, fontSize: fs, lineHeight: 1.6, color: glow > 0.1 ? C.cyanBright : C.text, display: "flex", alignItems: "center", gap: 12, paddingLeft: 26 }}>
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
            borderRadius: 10,
            border: `2px solid ${C.green}`,
            background: `${C.green}1A`,
            fontFamily: MONO,
            fontSize: fs,
            color: C.green,
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
  );
  const code = (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <Rise delay={112}>
        <Panel glow={C.cyan} style={{ padding: "24px 28px" }}>
          {[
            [["class ", C.redSoft], ["AwesomeTool", C.cyanBright], ["(DeviceModule):", C.text]],
            [["    device_type ", C.text], ["= ", C.muted], ['"PLC"', C.amber]],
            [["    vendor_id ", C.text], ["= ", C.muted], ['"ACME"', C.amber]],
            [],
            [["    def ", C.redSoft], ["_parse", C.cyanBright], ["(cls, file, dev):", C.text]],
            [["        ...", C.dim]],
          ].map((tokens, i) => (
            <div key={i} style={{ fontFamily: MONO, fontSize: fs, lineHeight: 1.6, minHeight: fs * 1.6, whiteSpace: "pre", opacity: interpolate(frame, [118 + i * 5, 124 + i * 5], [0, 1], clamp) }}>
              {(tokens as Array<[string, string]>).map(([t, c], j) => (
                <span key={j} style={{ color: c }}>
                  {t}
                </span>
              ))}
            </div>
          ))}
        </Panel>
      </Rise>
      <Rise delay={156} y={16}>
        <div style={{ fontFamily: MONO, fontSize: pick(24, 21), color: C.text, background: "rgba(255,255,255,0.05)", border: `1px solid ${C.border}`, borderRadius: 12, padding: "12px 18px", whiteSpace: "pre" }}>
          <span style={{ color: C.cyan }}>$ </span>peat parse -d AwesomeTool -I awesome_module.py -- out.json
        </div>
      </Rise>
    </div>
  );
  return (
    <Feature
      step="MODULAR"
      icon={<Boxes size={40} color={C.cyanBright} />}
      title="Add a device with *one Python class*"
      sub="Each device is a self-contained module. Load your own at runtime."
      textWidth={520}
      visual={
        <div style={{ display: "flex", flexDirection: "column", gap: 22, width: "100%", maxWidth: 1000 }}>
          {tree}
          {code}
        </div>
      }
    />
  );
};
