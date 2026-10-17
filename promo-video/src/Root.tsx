import React from "react";
import { Composition } from "remotion";
import { Promo } from "./Promo";
import { buildTimeline, FPS, VARIANTS } from "./timeline";

const FORMATS = [
  { name: "Landscape", width: 1920, height: 1080 },
  { name: "Portrait", width: 1080, height: 1920 },
  { name: "Ultrawide", width: 3440, height: 1440 },
];

// One composition per version and format, e.g. "Promo-V3-Ultrawide".
export const RemotionRoot: React.FC = () => (
  <>
    {VARIANTS.flatMap((variant) => {
      const timeline = buildTimeline(variant);
      return FORMATS.map((f) => (
        <Composition
          key={`${variant.id}-${f.name}`}
          id={`Promo-${variant.id.toUpperCase()}-${f.name}`}
          component={Promo}
          defaultProps={{ variant, timeline }}
          durationInFrames={timeline.duration}
          fps={FPS}
          width={f.width}
          height={f.height}
        />
      ));
    })}
  </>
);
