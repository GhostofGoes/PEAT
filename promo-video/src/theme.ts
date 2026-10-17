import { loadFont } from "@remotion/fonts";
import inter400 from "@fontsource/inter/files/inter-latin-400-normal.woff2";
import inter500 from "@fontsource/inter/files/inter-latin-500-normal.woff2";
import inter600 from "@fontsource/inter/files/inter-latin-600-normal.woff2";
import inter700 from "@fontsource/inter/files/inter-latin-700-normal.woff2";
import inter800 from "@fontsource/inter/files/inter-latin-800-normal.woff2";
import mono400 from "@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff2";
import mono600 from "@fontsource/jetbrains-mono/files/jetbrains-mono-latin-600-normal.woff2";

// Fonts are bundled from npm (OFL-1.1) so rendering works without reaching Google Fonts.
export const FONT = "Inter";
export const MONO = "JetBrains Mono";

const faces: Array<[string, string, string]> = [
  [FONT, inter400, "400"],
  [FONT, inter500, "500"],
  [FONT, inter600, "600"],
  [FONT, inter700, "700"],
  [FONT, inter800, "800"],
  [MONO, mono400, "400"],
  [MONO, mono600, "600"],
];
for (const [family, url, weight] of faces) {
  loadFont({ family, url, weight, format: "woff2" });
}

export const C = {
  bg: "#05080F",
  text: "#F1F5F9",
  muted: "#94A3B8",
  dim: "#64748B",
  cyan: "#00ADD0",
  cyanBright: "#4FD8F2",
  red: "#EF4444",
  redSoft: "#F87171",
  amber: "#F59E0B",
  green: "#22C55E",
  panel: "rgba(13, 20, 36, 0.88)",
  border: "rgba(148, 163, 184, 0.18)",
};
