import React from "react";
import { AbsoluteFill, Audio, interpolate, Sequence, staticFile, useCurrentFrame } from "remotion";
import { linearTiming, TransitionSeries } from "@remotion/transitions";
import { Background } from "./components/Background";
import { VirtualCanvas } from "./layout";
import { enterTransition } from "./transitions";
import { LEAD, SceneContext, SceneId, T, Timeline, Variant } from "./timeline";
import { THEMES, ThemeContext } from "./theme";
import { BaselineScene, QuestionScene, ThreatScene, ToolingScene, TurnScene } from "./scenes/Problems";
import { CtaScene, DiffScene, FreeScene, ParseScene, PullScene, RevealScene, ScanScene } from "./scenes/Solution";
import { DevicesScene, LibraryScene, ModulesScene, PlatformsScene, SafetyScene, ValueScene } from "./scenes/Extended";

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
  safety: SafetyScene,
  devices: DevicesScene,
  value: ValueScene,
  platforms: PlatformsScene,
  library: LibraryScene,
  modules: ModulesScene,
  free: FreeScene,
  cta: CtaScene,
};

export const Promo: React.FC<{ variant: Variant; timeline: Timeline }> = ({ variant, timeline }) => {
  const frame = useCurrentFrame();
  const theme = THEMES[variant.theme];
  const { scenes, start, duration } = timeline;
  const turn = start.turn;
  // Danger palette through the pain points, shifting to the accent on the turn.
  const danger = interpolate(frame, [turn + 20, turn + 60], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const heat = interpolate(frame, [0, start.tooling + 60], [0.55, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const musicVolume = (f: number) =>
    interpolate(f, [0, 30, turn, turn + 45, duration - 90, duration], [0, 0.08, 0.08, 0.12, 0.12, 0], {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp",
    });

  return (
    <ThemeContext.Provider value={theme}>
      <AbsoluteFill style={{ fontFamily: theme.font, background: theme.bg }}>
        <VirtualCanvas>
          <Background danger={danger} heat={heat} />
          <TransitionSeries>
            {scenes.flatMap((s, i) => {
              const Scene = COMPONENTS[s.id];
              const items = [];
              if (i > 0) {
                items.push(
                  <TransitionSeries.Transition key={`t-${s.id}`} presentation={enterTransition(theme.transitions, s.id)} timing={linearTiming({ durationInFrames: T })} />,
                );
              }
              items.push(
                <TransitionSeries.Sequence key={s.id} durationInFrames={s.frames}>
                  <SceneContext.Provider value={s}>
                    <Scene />
                  </SceneContext.Provider>
                </TransitionSeries.Sequence>,
              );
              return items;
            })}
          </TransitionSeries>
        </VirtualCanvas>

        {scenes.map((s) => (
          <Sequence key={`vo-${s.id}`} from={start[s.id] + LEAD} durationInFrames={s.voiceFrames + 6} layout="none">
            <Audio src={staticFile(`voice/${s.key}.mp3`)} />
          </Sequence>
        ))}
        <Audio src={staticFile(`music/${variant.music}`)} volume={musicVolume} />
      </AbsoluteFill>
    </ThemeContext.Provider>
  );
};
