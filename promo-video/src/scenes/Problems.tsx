import React from "react";
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { Cpu, MonitorX, Server, ShieldQuestion } from "lucide-react";
import { C, FONT, MONO } from "../theme";
import { useLayout } from "../layout";
import { Eyebrow, Panel, Rise, Words, useEnter } from "../components/ui";

// Cue frames below are word timings from the voiceover (scene start + LEAD + word time).

const Stage: React.FC<{ children: React.ReactNode; gap?: number; center?: boolean }> = ({ children, gap = 48, center }) => {
  const { padding } = useLayout();
  return (
    <AbsoluteFill
      style={{
        padding,
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        alignItems: center ? "center" : "stretch",
        gap,
      }}
    >
      {children}
    </AbsoluteFill>
  );
};

/* ---------- 1. The threat ---------- */

const ATTACKS = [
  { year: "2010", name: "Stuxnet", what: "Rewrote PLC logic" },
  { year: "2016", name: "Industroyer", what: "Grid relays" },
  { year: "2017", name: "Triton", what: "Safety controller" },
  { year: "2022", name: "PIPEDREAM", what: "Multi-vendor PLC kit" },
  { year: "2024", name: "FrostyGoop", what: "Modbus heat outage" },
];

export const ThreatScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { isPortrait, pick } = useLayout();
  const line = interpolate(frame, [10, 55], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  const timeline = isPortrait ? (
    <div style={{ position: "relative", paddingLeft: 56, display: "flex", flexDirection: "column", gap: 44 }}>
      <div
        style={{
          position: "absolute",
          left: 15,
          top: 12,
          width: 4,
          height: `${line * 92}%`,
          background: `linear-gradient(${C.amber}, ${C.red})`,
          borderRadius: 2,
        }}
      />
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
          background: `linear-gradient(90deg, ${C.amber}, ${C.red})`,
          borderRadius: 2,
          boxShadow: `0 0 18px ${C.red}`,
        }}
      />
      {ATTACKS.map((a, i) => (
        <AttackNode key={a.name} {...a} delay={14 + i * 7} />
      ))}
    </div>
  );

  return (
    <Stage gap={pick(70, 90)}>
      <Eyebrow label="01 — THE THREAT IS REAL" color={C.amber} delay={4} />
      {timeline}
      <Words
        text="Attacks now target *the controllers themselves.*"
        delay={70}
        size={pick(100, 88)}
        accent={C.red}
      />
    </Stage>
  );
};

const AttackNode: React.FC<{ year: string; name: string; what: string; delay: number; vertical?: boolean }> = ({
  year,
  name,
  what,
  delay,
  vertical,
}) => {
  const p = useEnter(delay, { damping: 13, mass: 0.6 });
  const dot = (
    <div
      style={{
        position: vertical ? "absolute" : "relative",
        left: vertical ? -56 : undefined,
        top: vertical ? 10 : -40,
        width: 34,
        height: 34,
        borderRadius: 17,
        background: C.bg,
        border: `5px solid ${C.red}`,
        boxShadow: `0 0 24px ${C.red}`,
        transform: `scale(${p})`,
      }}
    />
  );
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
        fontFamily: FONT,
        width: vertical ? undefined : 330,
      }}
    >
      {dot}
      <div style={{ fontFamily: MONO, fontSize: 32, color: C.amber, marginTop: vertical ? 0 : -6 }}>{year}</div>
      <div style={{ fontSize: vertical ? 54 : 52, fontWeight: 800, color: C.text }}>{name}</div>
      <div style={{ fontSize: vertical ? 30 : 28, color: C.muted }}>{what}</div>
    </div>
  );
};

/* ---------- 2. The question ---------- */

export const QuestionScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { pick, isPortrait } = useLayout();
  const rn = spring({ frame: frame - 96, fps, config: { damping: 10, mass: 0.6 } });
  const icons = isPortrait ? 6 : 8;

  return (
    <Stage center gap={pick(46, 60)}>
      <Eyebrow label="02 — THE QUESTION" color={C.amber} delay={2} center />
      <div style={{ display: "flex", gap: pick(36, 26), marginBottom: 10 }}>
        {Array.from({ length: icons }).map((_, i) => {
          const p = spring({ frame: frame - 8 - i * 4, fps, config: { damping: 200 } });
          const flagged = frame > 60 + i * 3;
          return (
            <div
              key={i}
              style={{
                position: "relative",
                width: pick(110, 120),
                height: pick(110, 120),
                borderRadius: 24,
                border: `2px solid ${flagged ? `${C.red}AA` : C.border}`,
                background: flagged ? `${C.red}14` : "rgba(255,255,255,0.03)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                opacity: p,
                transform: `translateY(${(1 - p) * 30}px)`,
              }}
            >
              <Cpu size={pick(58, 62)} color={flagged ? C.redSoft : C.muted} strokeWidth={1.6} />
              {flagged ? (
                <div
                  style={{
                    position: "absolute",
                    top: -14,
                    right: -14,
                    width: 40,
                    height: 40,
                    borderRadius: 20,
                    background: C.red,
                    color: "white",
                    fontFamily: FONT,
                    fontWeight: 800,
                    fontSize: 28,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  ?
                </div>
              ) : null}
            </div>
          );
        })}
      </div>
      <Words text="Are your controllers *compromised?*" delay={22} stagger={6} size={pick(112, 96)} accent={C.red} align="center" />
      <div
        style={{
          opacity: Math.min(1, rn * 1.5),
          transform: `scale(${interpolate(rn, [0, 1], [1.6, 1])})`,
          fontFamily: FONT,
          fontWeight: 800,
          fontSize: pick(76, 72),
          color: C.amber,
          letterSpacing: "0.02em",
          padding: "10px 44px",
          borderRadius: 999,
          border: `3px solid ${C.amber}`,
          boxShadow: `0 0 50px ${C.amber}55`,
        }}
      >
        Right now?
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
  const frame = useCurrentFrame();
  const { isPortrait, pick } = useLayout();
  const fs = pick(32, 30);
  const blink = Math.floor(frame / 10) % 2 === 0 ? 1 : 0.55;

  const devicePanel = (
    <Rise delay={22} style={{ flex: 1 }}>
      <Panel style={{ padding: 36 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, fontFamily: FONT, fontSize: 28, fontWeight: 700, color: C.muted, marginBottom: 22 }}>
          <Server size={34} color={C.muted} /> ON THE DEVICE
        </div>
        {DEVICE_LINES.map(([k, v], i) => (
          <Rise key={k} delay={28 + i * 4} y={14}>
            <div style={{ fontFamily: MONO, fontSize: fs, lineHeight: 1.75, color: C.text }}>
              <span style={{ color: C.cyanBright }}>{k}</span> := "{v}"
            </div>
          </Rise>
        ))}
      </Panel>
    </Rise>
  );

  const goldenPanel = (
    <Rise delay={34} style={{ flex: 1 }}>
      <Panel style={{ padding: 36, border: `3px dashed ${C.dim}`, background: "rgba(13,20,36,0.5)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, fontFamily: FONT, fontSize: 28, fontWeight: 700, color: C.dim, marginBottom: 22 }}>
          <ShieldQuestion size={34} color={C.dim} /> GOLDEN CONFIG
        </div>
        {DEVICE_LINES.map(([k], i) => (
          <div key={k} style={{ fontFamily: MONO, fontSize: fs, lineHeight: 1.75, color: C.dim, filter: "blur(5px)", opacity: 0.6 }}>
            {k} := "{"?".repeat(4 + ((i * 3) % 5))}"
          </div>
        ))}
      </Panel>
    </Rise>
  );

  const vs = (
    <div
      style={{
        width: 110,
        height: 110,
        flexShrink: 0,
        borderRadius: 55,
        border: `4px solid ${C.red}`,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: FONT,
        fontWeight: 800,
        fontSize: 64,
        color: C.red,
        opacity: interpolate(frame, [44, 54], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
        boxShadow: `0 0 40px ${C.red}66`,
        alignSelf: "center",
      }}
    >
      ?
    </div>
  );

  return (
    <Stage gap={pick(50, 56)}>
      <Eyebrow label="03 — NO BASELINE" color={C.red} delay={2} />
      <Words text="Configs are rarely checked against a *golden baseline.*" delay={8} size={pick(80, 72)} accent={C.amber} stagger={5} />
      <div style={{ display: "flex", flexDirection: isPortrait ? "column" : "row", gap: 36, alignItems: "stretch" }}>
        {devicePanel}
        {vs}
        {goldenPanel}
      </div>
      <Rise delay={72} y={20}>
        <div style={{ fontFamily: MONO, fontSize: pick(34, 32), color: C.redSoft, opacity: blink }}>
          ● last compared to golden config: NEVER
        </div>
      </Rise>
    </Stage>
  );
};

/* ---------- 4. The tooling ---------- */

const TOOLS = ["Relay Setup", "PLC Studio", "RTU Manager", "Meter Config", "Drive Tool"];

export const ToolingScene: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const { isPortrait, pick } = useLayout();
  const priceP = spring({ frame: frame - 166, fps, config: { damping: 12, mass: 0.7 } });
  const price = Math.round(interpolate(frame, [166, 190], [0, 11000], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }));

  const stack = (
    <div style={{ position: "relative", width: pick(960, 940), height: pick(560, 640), flexShrink: 0 }}>
      {TOOLS.map((t, i) => {
        const p = spring({ frame: frame - 26 - i * 9, fps, config: { damping: 15 } });
        return (
          <div
            key={t}
            style={{
              position: "absolute",
              left: i * pick(62, 56),
              top: i * pick(70, 80),
              width: pick(660, 700),
              opacity: p,
              transform: `perspective(1200px) rotateY(${pick(-14, -8)}deg) rotateX(6deg) translateY(${(1 - p) * 60}px)`,
            }}
          >
            <Panel style={{ overflow: "hidden", borderRadius: 14 }}>
              <div style={{ height: 58, background: "#1E293B", display: "flex", alignItems: "center", padding: "0 22px", gap: 14, fontFamily: FONT, fontSize: 28, color: C.muted }}>
                <MonitorX size={30} color={C.redSoft} /> {t}.exe — 1 device
              </div>
              <div style={{ padding: 26, display: "flex", flexDirection: "column", gap: 14 }}>
                {[0.9, 0.6, 0.75].map((w, j) => (
                  <div key={j} style={{ height: 16, width: `${w * 100}%`, borderRadius: 8, background: "rgba(148,163,184,0.18)" }} />
                ))}
              </div>
            </Panel>
          </div>
        );
      })}
      <div
        style={{
          position: "absolute",
          right: pick(-10, 0),
          bottom: pick(10, 0),
          opacity: interpolate(frame, [95, 105], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
        }}
      >
        <div style={{ fontFamily: MONO, fontSize: 34, color: C.amber, background: `${C.amber}1A`, border: `2px solid ${C.amber}88`, borderRadius: 12, padding: "10px 20px" }}>
          + 1 Windows VM per vendor
        </div>
      </div>
    </div>
  );

  const priceCard = (
    <div
      style={{
        opacity: Math.min(1, priceP * 1.5),
        transform: `scale(${interpolate(priceP, [0, 1], [0.7, 1])})`,
        display: "flex",
        flexDirection: "column",
        alignItems: isPortrait ? "center" : "flex-start",
      }}
    >
      <div
        style={{
          fontFamily: FONT,
          fontWeight: 800,
          fontSize: pick(150, 150),
          color: C.red,
          letterSpacing: "-0.04em",
          textShadow: `0 0 60px ${C.red}88`,
          fontVariantNumeric: "tabular-nums",
        }}
      >
        ${price.toLocaleString("en-US")}
      </div>
      <div style={{ fontFamily: FONT, fontSize: 36, color: C.muted, fontWeight: 600 }}>for a single license seat</div>
    </div>
  );

  return (
    <Stage gap={pick(40, 60)}>
      <Eyebrow label="04 — THE TOOLING" color={C.red} delay={2} />
      <Words text="Vendor tools: *one device at a time.*" delay={6} size={pick(84, 78)} accent={C.red} stagger={4} />
      <div
        style={{
          display: "flex",
          flexDirection: isPortrait ? "column" : "row",
          alignItems: "center",
          justifyContent: "space-between",
          gap: pick(40, 70),
        }}
      >
        {stack}
        {priceCard}
      </div>
    </Stage>
  );
};

/* ---------- 5. The turn ---------- */

export const TurnScene: React.FC = () => {
  const { pick } = useLayout();
  return (
    <Stage center>
      <Words text="What if one tool could" delay={6} stagger={3} size={pick(100, 92)} align="center" color={C.muted} weight={700} />
      <Words text="*see them all?*" delay={34} stagger={5} size={pick(150, 140)} align="center" accent={C.cyanBright} style={{ marginTop: -20 }} />
    </Stage>
  );
};
