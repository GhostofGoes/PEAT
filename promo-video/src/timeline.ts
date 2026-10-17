import durations from "./voiceover-durations.json";

export const FPS = 30;
/** Transition length between scenes, in frames. */
export const T = 12;
/** Frames between a scene's start and its voiceover line. */
export const LEAD = 10;

export type SceneId = keyof typeof durations;

// `gap` is the breathing room (frames) after the line before the next scene's transition.
const PLAN: Array<{ id: SceneId; gap: number }> = [
  { id: "threat", gap: 14 },
  { id: "question", gap: 14 },
  { id: "baseline", gap: 14 },
  { id: "tooling", gap: 14 },
  { id: "turn", gap: 30 },
  { id: "reveal", gap: 10 },
  { id: "scan", gap: 22 },
  { id: "pull", gap: 10 },
  { id: "parse", gap: 18 },
  { id: "downstream", gap: 14 },
  { id: "proof", gap: 14 },
  { id: "free", gap: 16 },
  { id: "cta", gap: 78 },
];

export const SCENES = PLAN.map((s, i) => {
  const voiceFrames = Math.ceil(durations[s.id] * FPS);
  const isLast = i === PLAN.length - 1;
  return { ...s, voiceFrames, frames: LEAD + voiceFrames + s.gap + (isLast ? 0 : T) };
});

/** Absolute start frame of each scene, accounting for transition overlaps. */
export const SCENE_START: Record<SceneId, number> = (() => {
  const out = {} as Record<SceneId, number>;
  let t = 0;
  for (const s of SCENES) {
    out[s.id] = t;
    t += s.frames - T;
  }
  return out;
})();

export const DURATION = SCENES.reduce((sum, s) => sum + s.frames, 0) - (SCENES.length - 1) * T;
