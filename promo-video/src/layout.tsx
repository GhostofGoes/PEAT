import React, { createContext, useContext } from "react";
import { useVideoConfig } from "remotion";

type Canvas = { width: number; height: number };
const CanvasContext = createContext<Canvas | null>(null);

/**
 * Scenes are laid out on a virtual canvas. Landscape and portrait use the real frame size;
 * ultrawide (21:9) frames are scaled so the canvas is 1080px tall, which keeps every
 * font size and spacing tuned for 1080p while using the extra width.
 */
export const VirtualCanvas: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { width, height } = useVideoConfig();
  const ultrawide = width / height > 2;
  const scale = ultrawide ? height / 1080 : 1;
  const canvas = { width: width / scale, height: height / scale };
  return (
    <CanvasContext.Provider value={canvas}>
      <div
        style={{
          position: "absolute",
          left: 0,
          top: 0,
          width: canvas.width,
          height: canvas.height,
          transform: `scale(${scale})`,
          transformOrigin: "top left",
          overflow: "hidden",
        }}
      >
        {children}
      </div>
    </CanvasContext.Provider>
  );
};

/** Layout info shared by every scene, so one scene file serves 16:9, 9:16 and 21:9. */
export const useLayout = () => {
  const video = useVideoConfig();
  const { width, height } = useContext(CanvasContext) ?? video;
  const isPortrait = height > width;
  const isUltrawide = width / height > 2;
  // On ultrawide, wide side padding keeps content in a ~2000px column.
  const sidePad = isUltrawide ? Math.max(160, (width - 2050) / 2) : isPortrait ? 64 : 110;
  const vertPad = isPortrait ? 64 : 110;
  return {
    width,
    height,
    isPortrait,
    isUltrawide,
    padding: `${vertPad}px ${sidePad}px`,
    /** Pick a value by orientation (ultrawide uses the landscape value). */
    pick: <V,>(landscape: V, portrait: V): V => (isPortrait ? portrait : landscape),
  };
};
