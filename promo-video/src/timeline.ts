import durations from "./voiceover-durations.json";
import cuts from "./cuts.json";

export const FPS = 30;
/** Transition length between scenes, in frames. */
export const T = 12;
/** Frames between a scene's start and its voiceover line. */
export const LEAD = 10;

export type SceneId = keyof typeof durations;
/** "short" is the ~70s cut, "long" the ~100s cut. Scene order and gaps live in cuts.json. */
export type Cut = keyof typeof cuts;

export type Timeline = ReturnType<typeof buildTimeline>;

// `gap` is the breathing room (frames) after the line before the next scene's transition.
const buildTimeline = (plan: Array<{ id: string; gap: number }>) => {
  const scenes = plan.map((s, i) => {
    const id = s.id as SceneId;
    const voiceFrames = Math.ceil(durations[id] * FPS);
    const isLast = i === plan.length - 1;
    return { id, gap: s.gap, voiceFrames, frames: LEAD + voiceFrames + s.gap + (isLast ? 0 : T) };
  });

  // Absolute start frame of each scene, accounting for transition overlaps.
  const start = {} as Record<SceneId, number>;
  let t = 0;
  for (const s of scenes) {
    start[s.id] = t;
    t += s.frames - T;
  }

  const duration = scenes.reduce((sum, s) => sum + s.frames, 0) - (scenes.length - 1) * T;
  return { scenes, start, duration };
};

export const TIMELINES: Record<Cut, Timeline> = {
  short: buildTimeline(cuts.short),
  long: buildTimeline(cuts.long),
};
