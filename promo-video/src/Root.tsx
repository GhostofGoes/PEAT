import React from "react";
import { Composition } from "remotion";
import { Promo } from "./Promo";
import { FPS, TIMELINES } from "./timeline";

export const RemotionRoot: React.FC = () => (
  <>
    <Composition id="Promo-Landscape" component={Promo} defaultProps={{ cut: "short" as const }} durationInFrames={TIMELINES.short.duration} fps={FPS} width={1920} height={1080} />
    <Composition id="Promo-Portrait" component={Promo} defaultProps={{ cut: "short" as const }} durationInFrames={TIMELINES.short.duration} fps={FPS} width={1080} height={1920} />
    <Composition id="Promo-Long-Landscape" component={Promo} defaultProps={{ cut: "long" as const }} durationInFrames={TIMELINES.long.duration} fps={FPS} width={1920} height={1080} />
    <Composition id="Promo-Long-Portrait" component={Promo} defaultProps={{ cut: "long" as const }} durationInFrames={TIMELINES.long.duration} fps={FPS} width={1080} height={1920} />
  </>
);
