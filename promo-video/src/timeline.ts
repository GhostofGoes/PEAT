import { createContext, useContext } from "react";
import durations from "./voiceover-durations.json";
import wordTimes from "./word-times.json";
import v1 from "./variants/v1.json";
import v2 from "./variants/v2.json";
import v3 from "./variants/v3.json";
import v4 from "./variants/v4.json";
import v5 from "./variants/v5.json";
import type { ThemeName } from "./theme";

export const FPS = 30;
/** Transition length between scenes, in frames. */
export const T = 12;
/** Frames between a scene's start and its voiceover line. */
export const LEAD = 10;

export type SceneId =
  | "threat"
  | "question"
  | "baseline"
  | "tooling"
  | "turn"
  | "reveal"
  | "scan"
  | "pull"
  | "parse"
  | "downstream"
  | "safety"
  | "devices"
  | "platforms"
  | "library"
  | "modules"
  | "free"
  | "cta";

export type SceneSpec = {
  id: SceneId;
  /** Breathing room (frames) after the line, before the next scene's transition. */
  gap: number;
  /** Voiceover line. */
  vo: string;
  /** On-screen copy. Wrap accent words in *asterisks*. */
  text: Record<string, string | string[]>;
  /** Animation cue name → word in `vo` that triggers it ("word" or "word#2" for the 2nd match). */
  cues?: Record<string, string>;
};

export type Variant = { id: string; name: string; theme: ThemeName; music: string; scenes: SceneSpec[] };

export const VARIANTS = [v1, v2, v3, v4, v5] as unknown as Variant[];

type Durations = Record<string, number>;
type WordTimes = Record<string, Array<[string, number]>>;

export const voiceKey = (variant: string, scene: string) => `${variant}-${scene}`;

export const buildTimeline = (variant: Variant) => {
  const scenes = variant.scenes.map((s, i) => {
    const key = voiceKey(variant.id, s.id);
    const seconds = (durations as Durations)[key];
    if (seconds === undefined) throw new Error(`No voiceover clip for ${key}; run scripts/generate-clips.mjs`);
    const voiceFrames = Math.ceil(seconds * FPS);
    const isLast = i === variant.scenes.length - 1;
    return { ...s, key, voiceFrames, frames: LEAD + voiceFrames + s.gap + (isLast ? 0 : T) };
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

export type Timeline = ReturnType<typeof buildTimeline>;
export type TimedScene = Timeline["scenes"][number];

export const SceneContext = createContext<TimedScene | null>(null);

const useScene = () => {
  const scene = useContext(SceneContext);
  if (!scene) throw new Error("useScene must be used inside a scene");
  return scene;
};

/** On-screen copy for the current scene. */
export const useCopy = () => {
  const { text } = useScene();
  return {
    str: (key: string, fallback = "") => (typeof text[key] === "string" ? (text[key] as string) : fallback),
    list: (key: string) => (Array.isArray(text[key]) ? (text[key] as string[]) : []),
  };
};

const normalize = (w: string) => w.toLowerCase().replace(/[^a-z0-9]/g, "");

/**
 * Frame (relative to scene start) at which a cue word is spoken. Falls back to a
 * fraction of the voiceover line if the cue isn't defined or the word isn't found.
 */
export const useCue = () => {
  const scene = useScene();
  const words = (wordTimes as unknown as WordTimes)[scene.key] ?? [];
  return (name: string, fallback: number) => {
    const spec = scene.cues?.[name];
    if (spec) {
      const [word, nth] = spec.split("#");
      const target = normalize(word);
      let seen = 0;
      for (const [w, start] of words) {
        if (normalize(w).startsWith(target) && ++seen >= Number(nth ?? 1)) {
          return LEAD + Math.round(start * FPS);
        }
      }
    }
    return LEAD + Math.round(fallback * scene.voiceFrames);
  };
};
