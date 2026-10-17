import React from "react";
import { interpolate } from "remotion";
import type { TransitionPresentation, TransitionPresentationComponentProps } from "@remotion/transitions";

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
