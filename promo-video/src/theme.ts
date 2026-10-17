import { createContext, useContext } from "react";
import { loadFont } from "@remotion/fonts";
import inter400 from "@fontsource/inter/files/inter-latin-400-normal.woff2";
import inter500 from "@fontsource/inter/files/inter-latin-500-normal.woff2";
import inter600 from "@fontsource/inter/files/inter-latin-600-normal.woff2";
import inter700 from "@fontsource/inter/files/inter-latin-700-normal.woff2";
import inter800 from "@fontsource/inter/files/inter-latin-800-normal.woff2";
import plex400 from "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2";
import plex500 from "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-500-normal.woff2";
import plex600 from "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-600-normal.woff2";
import plex700 from "@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-700-normal.woff2";
import grotesk400 from "@fontsource/space-grotesk/files/space-grotesk-latin-400-normal.woff2";
import grotesk500 from "@fontsource/space-grotesk/files/space-grotesk-latin-500-normal.woff2";
import grotesk600 from "@fontsource/space-grotesk/files/space-grotesk-latin-600-normal.woff2";
import grotesk700 from "@fontsource/space-grotesk/files/space-grotesk-latin-700-normal.woff2";
import manrope400 from "@fontsource/manrope/files/manrope-latin-400-normal.woff2";
import manrope500 from "@fontsource/manrope/files/manrope-latin-500-normal.woff2";
import manrope600 from "@fontsource/manrope/files/manrope-latin-600-normal.woff2";
import manrope700 from "@fontsource/manrope/files/manrope-latin-700-normal.woff2";
import manrope800 from "@fontsource/manrope/files/manrope-latin-800-normal.woff2";
import sora400 from "@fontsource/sora/files/sora-latin-400-normal.woff2";
import sora500 from "@fontsource/sora/files/sora-latin-500-normal.woff2";
import sora600 from "@fontsource/sora/files/sora-latin-600-normal.woff2";
import sora700 from "@fontsource/sora/files/sora-latin-700-normal.woff2";
import sora800 from "@fontsource/sora/files/sora-latin-800-normal.woff2";
import mono400 from "@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2";
import mono600 from "@fontsource/jetbrains-mono/files/jetbrains-mono-latin-600-normal.woff2";
import plexMono400 from "@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2";
import plexMono600 from "@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-600-normal.woff2";
import spaceMono400 from "@fontsource/space-mono/files/space-mono-latin-400-normal.woff2";
import spaceMono700 from "@fontsource/space-mono/files/space-mono-latin-700-normal.woff2";

// Fonts are bundled from npm (all OFL-1.1) so rendering works without reaching Google Fonts.
const faces: Array<[string, string, string]> = [
  ["Inter", inter400, "400"],
  ["Inter", inter500, "500"],
  ["Inter", inter600, "600"],
  ["Inter", inter700, "700"],
  ["Inter", inter800, "800"],
  ["IBM Plex Sans", plex400, "400"],
  ["IBM Plex Sans", plex500, "500"],
  ["IBM Plex Sans", plex600, "600"],
  ["IBM Plex Sans", plex700, "700"],
  ["Space Grotesk", grotesk400, "400"],
  ["Space Grotesk", grotesk500, "500"],
  ["Space Grotesk", grotesk600, "600"],
  ["Space Grotesk", grotesk700, "700"],
  ["Manrope", manrope400, "400"],
  ["Manrope", manrope500, "500"],
  ["Manrope", manrope600, "600"],
  ["Manrope", manrope700, "700"],
  ["Manrope", manrope800, "800"],
  ["Sora", sora400, "400"],
  ["Sora", sora500, "500"],
  ["Sora", sora600, "600"],
  ["Sora", sora700, "700"],
  ["Sora", sora800, "800"],
  ["JetBrains Mono", mono400, "400"],
  ["JetBrains Mono", mono600, "600"],
  ["IBM Plex Mono", plexMono400, "400"],
  ["IBM Plex Mono", plexMono600, "600"],
  ["Space Mono", spaceMono400, "400"],
  ["Space Mono", spaceMono700, "700"],
];
for (const [family, url, weight] of faces) {
  loadFont({ family, url, weight, format: "woff2" });
}

export type BackgroundStyle = "grid" | "blueprint" | "scanlines" | "aurora" | "dots";
export type PanelStyle = "glass" | "outline" | "solid" | "soft";
export type TransitionStyle = "mixed" | "slide" | "fade" | "soft" | "zoom";

export type Theme = {
  name: string;
  dark: boolean;
  bg: string;
  bg2: string;
  text: string;
  muted: string;
  dim: string;
  /** Brand fills (buttons, glows). */
  accent: string;
  /** Accent used for text and icons; must be readable on `bg`. */
  accentHi: string;
  /** Text color on top of an `accent` fill. */
  accentInk: string;
  danger: string;
  dangerHi: string;
  warn: string;
  ok: string;
  panel: string;
  border: string;
  subtle: string;
  chrome: string;
  skeleton: string;
  shadow: string;
  vignette: string;
  font: string;
  mono: string;
  headWeight: number;
  tracking: string;
  radius: number;
  panelStyle: PanelStyle;
  bgStyle: BackgroundStyle;
  transitions: TransitionStyle;
  /** Layout of the opening attack history. */
  threatStyle: "timeline" | "cards";
};

const signal: Theme = {
  name: "Signal",
  dark: true,
  bg: "#05080F",
  bg2: "#0B1220",
  text: "#F1F5F9",
  muted: "#94A3B8",
  dim: "#64748B",
  accent: "#00ADD0",
  accentHi: "#4FD8F2",
  accentInk: "#03121A",
  danger: "#EF4444",
  dangerHi: "#F87171",
  warn: "#F59E0B",
  ok: "#22C55E",
  panel: "rgba(13, 20, 36, 0.88)",
  border: "rgba(148, 163, 184, 0.18)",
  subtle: "rgba(255, 255, 255, 0.04)",
  chrome: "#1E293B",
  skeleton: "rgba(148, 163, 184, 0.18)",
  shadow: "rgba(0, 0, 0, 0.55)",
  vignette: "rgba(0, 0, 0, 0.7)",
  font: "Inter",
  mono: "JetBrains Mono",
  headWeight: 800,
  tracking: "-0.025em",
  radius: 22,
  panelStyle: "glass",
  bgStyle: "grid",
  transitions: "mixed",
  threatStyle: "timeline",
};

const blueprint: Theme = {
  name: "Blueprint",
  dark: true,
  bg: "#0A2342",
  bg2: "#11305A",
  text: "#EAF4FF",
  muted: "#A3BCDB",
  dim: "#6D8BB3",
  accent: "#3FD0F5",
  accentHi: "#8BE6FF",
  accentInk: "#04213D",
  danger: "#FF6B5B",
  dangerHi: "#FF9A8D",
  warn: "#FFC857",
  ok: "#5DE29B",
  panel: "rgba(7, 27, 54, 0.82)",
  border: "rgba(139, 230, 255, 0.38)",
  subtle: "rgba(139, 230, 255, 0.06)",
  chrome: "#143A68",
  skeleton: "rgba(139, 230, 255, 0.22)",
  shadow: "rgba(2, 10, 24, 0.5)",
  vignette: "rgba(2, 12, 28, 0.55)",
  font: "IBM Plex Sans",
  mono: "IBM Plex Mono",
  headWeight: 700,
  tracking: "-0.015em",
  radius: 4,
  panelStyle: "outline",
  bgStyle: "blueprint",
  transitions: "slide",
  threatStyle: "cards",
};

const controlRoom: Theme = {
  name: "Control Room",
  dark: true,
  bg: "#060908",
  bg2: "#0E1513",
  text: "#E6F2EC",
  muted: "#93AB9F",
  dim: "#5E7469",
  accent: "#22D39A",
  accentHi: "#6FF0C3",
  accentInk: "#02140D",
  danger: "#FF4D4D",
  dangerHi: "#FF8585",
  warn: "#FFB020",
  ok: "#22D39A",
  panel: "rgba(12, 19, 17, 0.94)",
  border: "rgba(111, 240, 195, 0.22)",
  subtle: "rgba(111, 240, 195, 0.05)",
  chrome: "#16211E",
  skeleton: "rgba(111, 240, 195, 0.16)",
  shadow: "rgba(0, 0, 0, 0.6)",
  vignette: "rgba(0, 0, 0, 0.75)",
  font: "Space Grotesk",
  mono: "Space Mono",
  headWeight: 700,
  tracking: "-0.02em",
  radius: 10,
  panelStyle: "solid",
  bgStyle: "scanlines",
  transitions: "fade",
  threatStyle: "timeline",
};

const daylight: Theme = {
  name: "Daylight",
  dark: false,
  bg: "#F4F7FA",
  bg2: "#FFFFFF",
  text: "#0B1B2B",
  muted: "#475569",
  dim: "#94A3B8",
  accent: "#00ADD0",
  accentHi: "#0083A3",
  accentInk: "#FFFFFF",
  danger: "#DC2626",
  dangerHi: "#E11D48",
  warn: "#C2410C",
  ok: "#15803D",
  panel: "rgba(255, 255, 255, 0.94)",
  border: "rgba(15, 23, 42, 0.10)",
  subtle: "rgba(15, 23, 42, 0.04)",
  chrome: "#E8EEF4",
  skeleton: "rgba(15, 23, 42, 0.10)",
  shadow: "rgba(15, 23, 42, 0.14)",
  vignette: "rgba(244, 247, 250, 0)",
  font: "Manrope",
  mono: "JetBrains Mono",
  headWeight: 800,
  tracking: "-0.025em",
  radius: 26,
  panelStyle: "soft",
  bgStyle: "aurora",
  transitions: "soft",
  threatStyle: "cards",
};

const kinetic: Theme = {
  name: "Kinetic",
  dark: true,
  bg: "#000000",
  bg2: "#0B0B0D",
  text: "#FFFFFF",
  muted: "#A1A1AA",
  dim: "#6B6B75",
  accent: "#00E5FF",
  accentHi: "#5CF2FF",
  accentInk: "#001418",
  danger: "#FF2E63",
  dangerHi: "#FF6B8F",
  warn: "#FFD60A",
  ok: "#00F5A0",
  panel: "rgba(16, 16, 20, 0.92)",
  border: "rgba(255, 255, 255, 0.14)",
  subtle: "rgba(255, 255, 255, 0.05)",
  chrome: "#18181D",
  skeleton: "rgba(255, 255, 255, 0.14)",
  shadow: "rgba(0, 0, 0, 0.6)",
  vignette: "rgba(0, 0, 0, 0.75)",
  font: "Sora",
  mono: "JetBrains Mono",
  headWeight: 800,
  tracking: "-0.035em",
  radius: 16,
  panelStyle: "glass",
  bgStyle: "dots",
  transitions: "zoom",
  threatStyle: "cards",
};

export const THEMES = { signal, blueprint, controlRoom, daylight, kinetic };
export type ThemeName = keyof typeof THEMES;

export const ThemeContext = createContext<Theme>(signal);
export const useTheme = () => useContext(ThemeContext);

/** `#RRGGBB` → `rgba(r, g, b, a)`. */
export const alpha = (hex: string, a: number) => {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
};
