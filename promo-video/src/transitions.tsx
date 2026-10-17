import React from "react";
import { interpolate } from "remotion";
import type { TransitionPresentation, TransitionPresentationComponentProps } from "@remotion/transitions";
import { slide } from "@remotion/transitions/slide";
import type { SceneId } from "./timeline";
import type { TransitionStyle } from "./theme";

type NoProps = Record<string, never>;

/** True crossfade: scenes are transparent over a shared background, so both sides must fade. */
const CrossfadePresentation: React.FC<TransitionPresentationComponentProps<NoProps>> = ({
  children,
  presentationDirection,
  presentationProgress,
}) => {
  const opacity = presentationDirection === "entering" ? presentationProgress : 1 - presentationProgress;
  return <div style={{ position: "absolute", inset: 0, opacity }}>{children}</div>;
};

export const crossfade = (): TransitionPresentation<NoProps> => ({ component: CrossfadePresentation, props: {} });

/** Crossfade plus a diagonal chrome shine band (no clipPath, see metallic-swoosh notes). */
const MetallicSwooshPresentation: React.FC<TransitionPresentationComponentProps<NoProps>> = ({
  children,
  presentationDirection,
  presentationProgress,
}) => {
  const isEntering = presentationDirection === "entering";
  const pos = interpolate(presentationProgress, [0, 1], [-20, 120]);
  const opacity = isEntering
    ? interpolate(presentationProgress, [0, 0.4, 1], [0, 1, 1])
    : interpolate(presentationProgress, [0, 0.35, 0.7], [1, 0.4, 0], { extrapolateRight: "clamp" });

  return (
    <div style={{ position: "absolute", inset: 0, opacity }}>
      {children}
      {isEntering && (
        <div
          style={{
            position: "absolute",
            inset: 0,
            pointerEvents: "none",
            background: `linear-gradient(105deg,
              transparent ${pos - 14}%,
              rgba(255,255,255,0) ${pos - 9}%,
              rgba(180,235,248,0.12) ${pos - 5}%,
              rgba(120,220,245,0.45) ${pos - 2}%,
              rgba(255,255,255,0.8) ${pos}%,
              rgba(140,225,245,0.45) ${pos + 2}%,
              rgba(180,235,248,0.12) ${pos + 5}%,
              rgba(255,255,255,0) ${pos + 9}%,
              transparent ${pos + 14}%)`,
          }}
        />
      )}
    </div>
  );
};

export const metallicSwoosh = (): TransitionPresentation<NoProps> => ({ component: MetallicSwooshPresentation, props: {} });

/** 2D zoom-through: the old scene pushes forward and fades, the new one settles in from slightly small. */
const ZoomPresentation: React.FC<TransitionPresentationComponentProps<NoProps>> = ({ children, presentationDirection, presentationProgress }) => {
  const entering = presentationDirection === "entering";
  const scale = entering ? interpolate(presentationProgress, [0, 1], [0.86, 1]) : interpolate(presentationProgress, [0, 1], [1, 1.3]);
  const opacity = entering ? interpolate(presentationProgress, [0, 0.6], [0, 1], { extrapolateRight: "clamp" }) : interpolate(presentationProgress, [0.2, 0.8], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return <div style={{ position: "absolute", inset: 0, opacity, transform: `scale(${scale})` }}>{children}</div>;
};

export const zoom = (): TransitionPresentation<NoProps> => ({ component: ZoomPresentation, props: {} });

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Presentation = TransitionPresentation<any>;

const FEATURES: SceneId[] = ["pull", "parse", "downstream", "modules"];
const SECTIONS: SceneId[] = ["reveal", "scan", "safety", "devices", "library", "cta"];

/** Transition into `scene` for a theme's transition style. */
export const enterTransition = (style: TransitionStyle, scene: SceneId): Presentation => {
  const isFeature = FEATURES.includes(scene);
  const isSection = SECTIONS.includes(scene);
  switch (style) {
    case "slide":
      return slide({ direction: isSection ? "from-bottom" : "from-right" });
    case "fade":
      return scene === "reveal" || scene === "cta" ? metallicSwoosh() : crossfade();
    case "soft":
      return isFeature ? slide({ direction: "from-right" }) : crossfade();
    case "zoom":
      return scene === "reveal" ? metallicSwoosh() : zoom();
    case "mixed":
    default:
      return isFeature ? slide({ direction: "from-right" }) : isSection ? metallicSwoosh() : crossfade();
  }
};
