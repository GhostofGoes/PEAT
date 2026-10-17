import React from "react";
import { random, useCurrentFrame } from "remotion";
import { alpha, useTheme } from "../theme";

// Stylized controller hardware drawn in SVG so it picks up each theme's colors.

const useBlink = (period: number, phase = 0) => {
  const frame = useCurrentFrame();
  return Math.floor((frame + phase) / period) % 2 === 0;
};

const Led: React.FC<{ x: number; y: number; color: string; on: boolean; r?: number }> = ({ x, y, color, on, r = 5 }) => (
  <>
    {on ? <circle cx={x} cy={y} r={r * 2.4} fill={alpha(color, 0.25)} /> : null}
    <circle cx={x} cy={y} r={r} fill={on ? color : alpha(color, 0.18)} />
  </>
);

/** Modular PLC on a DIN rail: power supply, CPU and four I/O cards. */
export const PlcRack: React.FC<{ width: number; alarm?: boolean }> = ({ width, alarm }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const errOn = useBlink(9);
  const body = C.dark ? C.chrome : "#DCE3EA";
  const card = C.dark ? C.bg2 : "#FFFFFF";
  const stroke = C.dark ? alpha(C.text, 0.18) : alpha(C.text, 0.22);
  return (
    <svg width={width} height={width * 0.5} viewBox="0 0 600 300">
      <rect x="0" y="136" width="600" height="28" rx="3" fill={alpha(C.muted, 0.35)} />
      {Array.from({ length: 24 }).map((_, i) => (
        <rect key={i} x={8 + i * 25} y="146" width="14" height="8" rx="2" fill={alpha(C.bg, 0.6)} />
      ))}
      {/* power supply */}
      <rect x="20" y="30" width="80" height="240" rx="8" fill={body} stroke={stroke} strokeWidth="2" />
      {Array.from({ length: 9 }).map((_, i) => (
        <rect key={i} x="34" y={110 + i * 14} width="52" height="5" rx="2" fill={alpha(C.bg, 0.5)} />
      ))}
      <Led x={60} y={60} color={C.ok} on />
      <text x="60" y="90" textAnchor="middle" fontFamily={C.mono} fontSize="16" fill={C.muted}>PWR</text>
      {/* CPU */}
      <rect x="110" y="30" width="120" height="240" rx="8" fill={body} stroke={alarm ? C.danger : stroke} strokeWidth={alarm ? 4 : 2} />
      <rect x="124" y="46" width="92" height="44" rx="4" fill={alpha(C.accent, 0.18)} stroke={alpha(C.accent, 0.5)} />
      <text x="170" y="74" textAnchor="middle" fontFamily={C.mono} fontSize="17" fill={C.accentHi}>{alarm ? "??:??" : "RUN"}</text>
      <Led x={136} y={112} color={C.ok} on />
      <text x="152" y="118" fontFamily={C.mono} fontSize="15" fill={C.muted}>RUN</text>
      <Led x={136} y={138} color={C.danger} on={!!alarm && errOn} />
      <text x="152" y="144" fontFamily={C.mono} fontSize="15" fill={C.muted}>ERR</text>
      <circle cx="170" cy="190" r="18" fill={card} stroke={stroke} strokeWidth="3" />
      <rect x="167" y="176" width="6" height="16" rx="2" fill={C.muted} />
      {[0, 1].map((i) => (
        <rect key={i} x={128 + i * 46} y="226" width="38" height="28" rx="3" fill={alpha(C.bg, 0.7)} stroke={stroke} />
      ))}
      {/* I/O cards */}
      {Array.from({ length: 4 }).map((_, m) => {
        const x = 240 + m * 88;
        return (
          <g key={m}>
            <rect x={x} y="30" width="80" height="240" rx="8" fill={card} stroke={stroke} strokeWidth="2" />
            {Array.from({ length: 8 }).map((_, i) => {
              const on = random(`io-${m}-${i}-${Math.floor((frame + m * 7) / 18)}`) > 0.45;
              return <Led key={i} x={x + 14 + (i % 4) * 17} y={48 + Math.floor(i / 4) * 16} r={4} color={C.ok} on={on} />;
            })}
            {Array.from({ length: 8 }).map((_, i) => (
              <g key={i}>
                <rect x={x + 10} y={90 + i * 21} width="60" height="16" rx="2" fill={alpha(C.muted, 0.22)} />
                <circle cx={x + 22} cy={98 + i * 21} r="5" fill={alpha(C.bg, 0.7)} />
                <circle cx={x + 58} cy={98 + i * 21} r="5" fill={alpha(C.bg, 0.7)} />
              </g>
            ))}
          </g>
        );
      })}
    </svg>
  );
};

/** Protective relay faceplate: LCD, target LEDs and navigation buttons. */
export const RelayPanel: React.FC<{ width: number; alarm?: boolean }> = ({ width, alarm }) => {
  const C = useTheme();
  const tripOn = useBlink(11, 4);
  const face = C.dark ? C.chrome : "#E3E9EF";
  const stroke = C.dark ? alpha(C.text, 0.18) : alpha(C.text, 0.22);
  return (
    <svg width={width} height={width * 1.1} viewBox="0 0 300 330">
      <rect x="4" y="4" width="292" height="322" rx="12" fill={face} stroke={alarm ? C.danger : stroke} strokeWidth={alarm ? 4 : 2} />
      <rect x="24" y="24" width="252" height="70" rx="6" fill={alpha(C.accent, 0.16)} stroke={alpha(C.accent, 0.5)} />
      <text x="40" y="54" fontFamily={C.mono} fontSize="17" fill={C.accentHi}>{alarm ? "SETTINGS CHANGED" : "51P1P   6.00 A"}</text>
      <text x="40" y="80" fontFamily={C.mono} fontSize="17" fill={C.accentHi}>{alarm ? "BY: ???" : "TRIP    51P1T"}</text>
      {["ENABLED", "TRIP", "INST", "TIME", "COMM", "SOTF", "ZONE 1", "ZONE 2"].map((label, i) => {
        const col = i % 2;
        const row = Math.floor(i / 2);
        const color = i === 0 ? C.ok : C.danger;
        const on = i === 0 || (i === 1 && !!alarm && tripOn);
        return (
          <g key={label}>
            <Led x={40 + col * 130} y={122 + row * 30} color={color} on={on} r={6} />
            <text x={56 + col * 130} y={128 + row * 30} fontFamily={C.mono} fontSize="15" fill={C.muted}>{label}</text>
          </g>
        );
      })}
      {Array.from({ length: 6 }).map((_, i) => (
        <rect key={i} x={30 + (i % 3) * 84} y={250 + Math.floor(i / 3) * 34} width="70" height="24" rx="6" fill={alpha(C.bg, C.dark ? 0.6 : 0.9)} stroke={stroke} />
      ))}
    </svg>
  );
};

/** Remote terminal unit: network ports, status LEDs and a field terminal strip. */
export const RtuUnit: React.FC<{ width: number; alarm?: boolean }> = ({ width, alarm }) => {
  const C = useTheme();
  const frame = useCurrentFrame();
  const body = C.dark ? C.chrome : "#E3E9EF";
  const stroke = C.dark ? alpha(C.text, 0.18) : alpha(C.text, 0.22);
  return (
    <svg width={width} height={width * 1.1} viewBox="0 0 300 330">
      <rect x="4" y="4" width="292" height="322" rx="12" fill={body} stroke={alarm ? C.danger : stroke} strokeWidth={alarm ? 4 : 2} />
      <text x="24" y="44" fontFamily={C.mono} fontSize="20" fontWeight="600" fill={C.text}>RTU</text>
      {Array.from({ length: 4 }).map((_, i) => (
        <g key={i}>
          <rect x={24 + i * 66} y="66" width="54" height="44" rx="4" fill={alpha(C.bg, 0.75)} stroke={stroke} />
          <rect x={38 + i * 66} y="72" width="26" height="10" rx="2" fill={alpha(C.muted, 0.4)} />
          <Led x={32 + i * 66} y={124} r={4} color={C.ok} on={random(`rtu-${i}-${Math.floor((frame + i * 5) / 8)}`) > 0.35} />
        </g>
      ))}
      {["PWR", "RUN", "ALM", "COM"].map((label, i) => (
        <g key={label}>
          <Led x={36} y={160 + i * 26} color={label === "ALM" ? C.danger : C.ok} on={label === "ALM" ? !!alarm : true} r={6} />
          <text x="52" y={166 + i * 26} fontFamily={C.mono} fontSize="15" fill={C.muted}>{label}</text>
        </g>
      ))}
      {Array.from({ length: 10 }).map((_, i) => (
        <g key={i}>
          <rect x={150 + (i % 2) * 64} y={150 + Math.floor(i / 2) * 26} width="56" height="20" rx="2" fill={alpha(C.muted, 0.22)} />
          <circle cx={163 + (i % 2) * 64} cy={160 + Math.floor(i / 2) * 26} r="5" fill={alpha(C.bg, 0.7)} />
        </g>
      ))}
    </svg>
  );
};
