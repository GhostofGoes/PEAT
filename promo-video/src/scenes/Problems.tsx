import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { Lock, Server, ShieldOff, ShieldQuestion } from "lucide-react";
import { alpha, useTheme } from "../theme";
import { useLayout } from "../layout";
import { useCopy, useCue } from "../timeline";
import { clamp, Eyebrow, Panel, Rise, Stage, Words, useEnter } from "../components/ui";
import { PlcRack, RelayPanel, RtuUnit } from "../components/Hardware";

/* ---------- 1. The threat ---------- */

const ATTACKS = [
  { year: "2010", name: "Stuxnet", what: "Rewrote PLC logic" },
  { year: "2016", name: "Industroyer", what: "Grid relays" },
  { year: "2017", name: "Triton", what: "Safety controller" },
  { year: "2022", name: "PIPEDREAM", what: "Multi-vendor PLC kit" },
  { year: "2024", name: "FrostyGoop", what: "Modbus heat outage" },
];

export const ThreatScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { isPortrait, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const line = interpolate(frame, [10, 55], [0, 1], clamp);

  const timeline =
    C.threatStyle === "cards" ? (
      <div style={{ display: "grid", gridTemplateColumns: pick("repeat(5, 1fr)", "1fr 1fr"), gap: pick(22, 20) }}>
        {ATTACKS.map((a, i) => (
          <AttackCard key={a.name} {...a} delay={12 + i * 7} wide={isPortrait && i === 4} />
        ))}
      </div>
    ) : isPortrait ? (
      <div style={{ position: "relative", paddingLeft: 56, display: "flex", flexDirection: "column", gap: 44 }}>
        <div style={{ position: "absolute", left: 15, top: 12, width: 4, height: `${line * 92}%`, background: `linear-gradient(${C.warn}, ${C.danger})`, borderRadius: 2 }} />
        {ATTACKS.map((a, i) => (
          <AttackNode key={a.name} {...a} delay={14 + i * 7} vertical />
        ))}
      </div>
    ) : (
      <div style={{ position: "relative", display: "flex", justifyContent: "space-between", paddingTop: 40 }}>
        <div
          style={{
            position: "absolute",
            left: 0,
            top: 14,
            height: 4,
            width: `${line * 100}%`,
            background: `linear-gradient(90deg, ${C.warn}, ${C.danger})`,
            borderRadius: 2,
            boxShadow: C.dark ? `0 0 18px ${C.danger}` : undefined,
          }}
        />
        {ATTACKS.map((a, i) => (
          <AttackNode key={a.name} {...a} delay={14 + i * 7} />
        ))}
      </div>
    );

  return (
    <Stage gap={pick(70, 90)}>
      <Eyebrow label={copy.str("eyebrow")} color={C.warn} delay={4} />
      {timeline}
      <Words text={copy.str("headline")} delay={cue("headline", 0.45)} size={pick(96, 84)} accent={C.danger} />
    </Stage>
  );
};

const AttackNode: React.FC<{ year: string; name: string; what: string; delay: number; vertical?: boolean }> = ({ year, name, what, delay, vertical }) => {
  const C = useTheme();
  const p = useEnter(delay, { damping: 13, mass: 0.6 });
  return (
    <div
      style={{
        position: "relative",
        display: "flex",
        flexDirection: "column",
        alignItems: vertical ? "flex-start" : "center",
        gap: 6,
        opacity: Math.min(1, p * 1.4),
        transform: `translateY(${(1 - p) * 30}px)`,
        fontFamily: C.font,
        width: vertical ? undefined : 330,
      }}
    >
      <div
        style={{
          position: vertical ? "absolute" : "relative",
          left: vertical ? -56 : undefined,
          top: vertical ? 10 : -40,
          width: 34,
          height: 34,
          borderRadius: 17,
          background: C.bg,
          border: `5px solid ${C.danger}`,
          boxShadow: C.dark ? `0 0 24px ${C.danger}` : undefined,
          transform: `scale(${p})`,
        }}
      />
      <div style={{ fontFamily: C.mono, fontSize: 32, color: C.warn, marginTop: vertical ? 0 : -6 }}>{year}</div>
      <div style={{ fontSize: vertical ? 54 : 52, fontWeight: C.headWeight, color: C.text }}>{name}</div>
      <div style={{ fontSize: vertical ? 30 : 28, color: C.muted }}>{what}</div>
    </div>
  );
};

const AttackCard: React.FC<{ year: string; name: string; what: string; delay: number; wide?: boolean }> = ({ year, name, what, delay, wide }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const p = useEnter(delay, { damping: 14, mass: 0.6 });
  const flash = interpolate(frame, [delay, delay + 6, delay + 26], [0, 1, 0.25], clamp);
  return (
    <div style={{ gridColumn: wide ? "1 / -1" : undefined, opacity: Math.min(1, p * 1.4), transform: `translateY(${(1 - p) * 40}px)` }}>
      <Panel glow={flash > 0.3 ? C.danger : undefined} style={{ padding: "28px 26px", borderTop: `6px solid ${alpha(C.danger, 0.4 + flash * 0.6)}` }}>
        <div style={{ fontFamily: C.mono, fontSize: 30, color: C.warn }}>{year}</div>
        <div style={{ fontFamily: C.font, fontSize: 50, fontWeight: C.headWeight, color: C.text, letterSpacing: C.tracking }}>{name}</div>
        <div style={{ fontFamily: C.font, fontSize: 27, color: C.muted }}>{what}</div>
      </Panel>
    </div>
  );
};

/* ---------- 2. The question: are your controllers compromised? ---------- */

const DeviceSlot: React.FC<{ label: string; delay: number; alarmAt: number; children: (alarm: boolean) => React.ReactNode }> = ({
  label,
  delay,
  alarmAt,
  children,
}) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - delay, fps, config: { damping: 200 } });
  const alarm = frame >= alarmAt;
  const badge = spring({ frame: frame - alarmAt, fps, config: { damping: 9, mass: 0.5 } });
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, opacity: p, transform: `translateY(${(1 - p) * 40}px)` }}>
      <div style={{ position: "relative", filter: alarm && C.dark ? `drop-shadow(0 0 24px ${alpha(C.danger, 0.45)})` : undefined }}>
        {children(alarm)}
        <div
          style={{
            position: "absolute",
            top: -22,
            right: -22,
            width: 58,
            height: 58,
            borderRadius: 29,
            background: C.danger,
            color: "#FFFFFF",
            fontFamily: C.font,
            fontWeight: 800,
            fontSize: 38,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            opacity: Math.min(1, badge * 1.5),
            transform: `scale(${badge})`,
            boxShadow: `0 6px 20px ${alpha(C.danger, 0.5)}`,
          }}
        >
          ?
        </div>
      </div>
      <div style={{ fontFamily: C.mono, fontSize: 24, letterSpacing: "0.14em", color: alarm ? C.dangerHi : C.muted }}>{label}</div>
    </div>
  );
};

export const QuestionScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { pick, isPortrait } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const headlineAt = cue("headline", 0.25);
  const kickerAt = cue("kicker", 0.75);
  const k = spring({ frame: frame - kickerAt, fps, config: { damping: 10, mass: 0.6 } });

  const plc = <DeviceSlot label="PLC" delay={6} alarmAt={headlineAt + 10}>{(a) => <PlcRack width={pick(760, 900)} alarm={a} />}</DeviceSlot>;
  const relay = <DeviceSlot label="RELAY" delay={12} alarmAt={headlineAt + 16}>{(a) => <RelayPanel width={pick(310, 360)} alarm={a} />}</DeviceSlot>;
  const rtu = <DeviceSlot label="RTU" delay={18} alarmAt={headlineAt + 22}>{(a) => <RtuUnit width={pick(310, 360)} alarm={a} />}</DeviceSlot>;

  return (
    <Stage center gap={pick(34, 56)}>
      <Eyebrow label={copy.str("eyebrow")} color={C.warn} delay={2} center />
      {isPortrait ? (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 40 }}>
          {plc}
          <div style={{ display: "flex", gap: 70 }}>
            {relay}
            {rtu}
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", alignItems: "flex-end", gap: 70 }}>
          {plc}
          {relay}
          {rtu}
        </div>
      )}
      <Words text={copy.str("headline")} delay={headlineAt} stagger={5} size={pick(86, 84)} accent={C.danger} align="center" />
      <div
        style={{
          opacity: Math.min(1, k * 1.5),
          transform: `scale(${interpolate(k, [0, 1], [1.5, 1])})`,
          fontFamily: C.font,
          fontWeight: C.headWeight,
          fontSize: pick(64, 60),
          color: C.warn,
          padding: "8px 42px",
          borderRadius: C.radius <= 6 ? C.radius : 999,
          border: `3px solid ${C.warn}`,
          boxShadow: C.dark ? `0 0 50px ${alpha(C.warn, 0.33)}` : undefined,
          textAlign: "center",
        }}
      >
        {copy.str("kicker")}
      </div>
    </Stage>
  );
};

/* ---------- 3. No golden baseline ---------- */

const DEVICE_LINES = [
  ["IPADDR", "10.20.1.15/24"],
  ["TELNET", "ENABLED"],
  ["51P1P", "60.00"],
  ["TR", "0"],
  ["SER", "DISABLED"],
];

export const BaselineScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { isPortrait, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const fs = pick(32, 30);
  const blink = Math.floor(frame / 10) % 2 === 0 ? 1 : 0.55;

  return (
    <Stage gap={pick(50, 56)}>
      <Eyebrow label={copy.str("eyebrow")} color={C.danger} delay={2} />
      <Words text={copy.str("headline")} delay={8} size={pick(76, 70)} accent={C.warn} stagger={5} />
      <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", gap: 36, alignItems: "stretch" }}>
        <Rise delay={22} style={{ flex: 1 }}>
          <Panel style={{ padding: 36 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 14, fontFamily: C.font, fontSize: 28, fontWeight: 700, color: C.muted, marginBottom: 22 }}>
              <Server size={34} color={C.muted} /> ON THE DEVICE
            </div>
            {DEVICE_LINES.map(([k, v], i) => (
              <Rise key={k} delay={28 + i * 4} y={14}>
                <div style={{ fontFamily: C.mono, fontSize: fs, lineHeight: 1.75, color: C.text }}>
                  <span style={{ color: C.accentHi }}>{k}</span> := "{v}"
                </div>
              </Rise>
            ))}
          </Panel>
        </Rise>
        <div
          style={{
            width: 110,
            height: 110,
            flexShrink: 0,
            borderRadius: 55,
            border: `4px solid ${C.danger}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontFamily: C.font,
            fontWeight: 800,
            fontSize: 64,
            color: C.danger,
            opacity: interpolate(frame, [44, 54], [0, 1], clamp),
            boxShadow: C.dark ? `0 0 40px ${alpha(C.danger, 0.4)}` : undefined,
            alignSelf: "center",
          }}
        >
          ?
        </div>
        <Rise delay={34} style={{ flex: 1 }}>
          <Panel style={{ padding: 36, border: `3px dashed ${C.dim}`, background: C.subtle }}>
            <div style={{ display: "flex", alignItems: "center", gap: 14, fontFamily: C.font, fontSize: 28, fontWeight: 700, color: C.dim, marginBottom: 22 }}>
              <ShieldQuestion size={34} color={C.dim} /> GOLDEN CONFIG
            </div>
            {DEVICE_LINES.map(([k], i) => (
              <div key={k} style={{ fontFamily: C.mono, fontSize: fs, lineHeight: 1.75, color: C.dim, filter: "blur(5px)", opacity: 0.6 }}>
                {k} := "{"?".repeat(4 + ((i * 3) % 5))}"
              </div>
            ))}
          </Panel>
        </Rise>
      </div>
      <Rise delay={cue("status", 0.7)} y={20}>
        <div style={{ fontFamily: C.mono, fontSize: pick(34, 30), color: C.dangerHi, opacity: blink }}>● {copy.str("status")}</div>
      </Rise>
    </Stage>
  );
};

/* ---------- 4. The tooling ---------- */

const TOOLS = ["RelaySetup", "PLC Studio", "RTU Manager", "DriveTool", "MeterConfig"];

export const ToolingScene: React.FC = () => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { isPortrait, pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  const costAt = cue("cost", 0.45);
  const securityAt = cue("security", 0.8);
  const costP = spring({ frame: frame - costAt, fps, config: { damping: 12, mass: 0.7 } });
  const secP = spring({ frame: frame - securityAt, fps, config: { damping: 12, mass: 0.7 } });

  const stack = (
    <div style={{ position: "relative", width: pick(900, 900), height: pick(540, 560), flexShrink: 0 }}>
      {TOOLS.map((t, i) => {
        const p = spring({ frame: frame - 14 - i * 9, fps, config: { damping: 15 } });
        return (
          <div
            key={t}
            style={{
              position: "absolute",
              left: i * pick(58, 52),
              top: i * pick(66, 72),
              width: pick(640, 640),
              opacity: p,
              transform: `perspective(1200px) rotateY(${pick(-14, -8)}deg) rotateX(6deg) translateY(${(1 - p) * 60}px)`,
            }}
          >
            <Panel style={{ overflow: "hidden", borderRadius: Math.min(C.radius, 14) }}>
              <div style={{ height: 58, background: C.chrome, display: "flex", alignItems: "center", padding: "0 22px", gap: 14, fontFamily: C.font, fontSize: 27, color: C.muted }}>
                <Lock size={26} color={C.warn} /> {t}.exe <span style={{ marginLeft: "auto", fontSize: 22, color: C.dim }}>proprietary</span>
              </div>
              <div style={{ padding: 26, display: "flex", flexDirection: "column", gap: 14 }}>
                {[0.9, 0.6, 0.75].map((w, j) => (
                  <div key={j} style={{ height: 16, width: `${w * 100}%`, borderRadius: 8, background: C.skeleton }} />
                ))}
              </div>
            </Panel>
          </div>
        );
      })}
    </div>
  );

  const callout = (p: number, icon: React.ReactNode, big: string, small: string, color: string) => (
    <div style={{ opacity: Math.min(1, p * 1.5), transform: `scale(${interpolate(p, [0, 1], [0.75, 1])})`, transformOrigin: "left center" }}>
      <Panel glow={color} style={{ padding: "26px 34px", display: "flex", alignItems: "center", gap: 26 }}>
        {icon}
        <div>
          <div style={{ fontFamily: C.font, fontWeight: C.headWeight, fontSize: pick(64, 60), color, letterSpacing: C.tracking, lineHeight: 1.05 }}>{big}</div>
          <div style={{ fontFamily: C.font, fontSize: pick(30, 28), color: C.muted, fontWeight: 600 }}>{small}</div>
        </div>
      </Panel>
    </div>
  );

  return (
    <Stage gap={pick(40, 56)}>
      <Eyebrow label={copy.str("eyebrow")} color={C.danger} delay={2} />
      <Words text={copy.str("headline")} delay={6} size={pick(80, 74)} accent={C.danger} stagger={4} />
      <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", alignItems: "center", justifyContent: "space-between", gap: pick(40, 50) }}>
        {stack}
        <div style={{ display: "flex", flexDirection: "column", gap: 28, alignItems: "stretch" }}>
          {callout(costP, <div style={{ fontFamily: C.font, fontWeight: 800, fontSize: 60, color: C.warn, width: 90, textAlign: "center" }}>$$</div>, copy.str("cost"), copy.str("costSub"), C.warn)}
          {callout(secP, <ShieldOff size={84} color={C.danger} strokeWidth={1.6} />, copy.str("security"), copy.str("securitySub"), C.danger)}
        </div>
      </div>
    </Stage>
  );
};

/* ---------- 5. The turn ---------- */

export const TurnScene: React.FC = () => {
  const C = useTheme();
  const { pick } = useLayout();
  const copy = useCopy();
  const cue = useCue();
  return (
    <Stage center>
      <Words text={copy.str("line1")} delay={4} stagger={3} size={pick(96, 88)} align="center" color={C.muted} weight={700} />
      <Words text={copy.str("line2")} delay={cue("line2", 0.5)} stagger={5} size={pick(140, 120)} align="center" style={{ marginTop: -10 }} />
    </Stage>
  );
};
