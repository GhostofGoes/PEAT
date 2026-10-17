import React from "react";
import { AbsoluteFill, Audio, interpolate, Sequence, staticFile, useCurrentFrame } from "remotion";
import { linearTiming, TransitionSeries } from "@remotion/transitions";
import type { TransitionPresentation } from "@remotion/transitions";
import { slide } from "@remotion/transitions/slide";
import { Background } from "./components/Background";
import { crossfade, metallicSwoosh } from "./transitions";
import { Cut, LEAD, SceneId, T, TIMELINES } from "./timeline";
import { FONT } from "./theme";
import { BaselineScene, QuestionScene, ThreatScene, ToolingScene, TurnScene } from "./scenes/Problems";
import { CtaScene, DiffScene, FreeScene, ParseScene, ProofScene, PullScene, RevealScene, ScanScene } from "./scenes/Solution";
import { DevicesScene, LibraryScene, ModulesScene, PlatformsScene, PushScene } from "./scenes/Extended";

const COMPONENTS: Record<SceneId, React.FC> = {
  threat: ThreatScene,
  question: QuestionScene,
  baseline: BaselineScene,
  tooling: ToolingScene,
  turn: TurnScene,
  reveal: RevealScene,
  scan: ScanScene,
  pull: PullScene,
  parse: ParseScene,
  downstream: DiffScene,
  push: PushScene,
  devices: DevicesScene,
  platforms: PlatformsScene,
  library: LibraryScene,
  modules: ModulesScene,
  proof: ProofScene,
  free: FreeScene,
  cta: CtaScene,
};

// Transition INTO each scene (the first scene has none).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ENTER: Partial<Record<SceneId, () => TransitionPresentation<any>>> = {
  question: crossfade,
  baseline: crossfade,
  tooling: crossfade,
  turn: crossfade,
  reveal: metallicSwoosh,
  scan: metallicSwoosh,
  pull: () => slide({ direction: "from-right" }),
  parse: () => slide({ direction: "from-right" }),
  downstream: () => slide({ direction: "from-right" }),
  push: () => slide({ direction: "from-right" }),
  devices: metallicSwoosh,
  platforms: crossfade,
  library: metallicSwoosh,
  modules: () => slide({ direction: "from-right" }),
  proof: metallicSwoosh,
  free: crossfade,
  cta: metallicSwoosh,
};

export const Promo: React.FC<{ cut: Cut }> = ({ cut }) => {
  const frame = useCurrentFrame();
  const { scenes: SCENES, start: SCENE_START, duration: DURATION } = TIMELINES[cut];
  const turn = SCENE_START.turn;
  // Red "danger" palette through the pain points, shifting to PEAT cyan on "see them all".
  const danger = interpolate(frame, [turn + 20, turn + 60], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const heat = interpolate(frame, [0, SCENE_START.tooling + 60], [0.55, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const musicVolume = (f: number) =>
    interpolate(f, [0, 30, turn, turn + 45, DURATION - 90, DURATION], [0, 0.08, 0.08, 0.12, 0.12, 0], {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp",
    });

  return (
    <AbsoluteFill style={{ fontFamily: FONT }}>
      <Background danger={danger} heat={heat} />
      <TransitionSeries>
        {SCENES.flatMap((s, i) => {
          const Scene = COMPONENTS[s.id];
          const enter = ENTER[s.id];
          const items = [];
          if (i > 0 && enter) {
            items.push(
              <TransitionSeries.Transition key={`t-${s.id}`} presentation={enter()} timing={linearTiming({ durationInFrames: T })} />,
            );
          }
          items.push(
            <TransitionSeries.Sequence key={s.id} durationInFrames={s.frames}>
              <Scene />
            </TransitionSeries.Sequence>,
          );
          return items;
        })}
      </TransitionSeries>

      {SCENES.map((s) => (
        <Sequence key={`vo-${s.id}`} from={SCENE_START[s.id] + LEAD} durationInFrames={s.voiceFrames + 6} layout="none">
          <Audio src={staticFile(`voice/${s.id}.mp3`)} />
        </Sequence>
      ))}
      {/* The music bed is 85s; the long cut uses a copy crossfaded into itself (see README). */}
      <Audio src={staticFile(cut === "long" ? "music-long.mp3" : "music.mp3")} volume={musicVolume} />
    </AbsoluteFill>
  );
};
