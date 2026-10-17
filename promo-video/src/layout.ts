import { useVideoConfig } from "remotion";

/** Layout info shared by every scene, so one scene file serves 16:9 and 9:16. */
export const useLayout = () => {
  const { width, height } = useVideoConfig();
  const isPortrait = height > width;
  return {
    width,
    height,
    isPortrait,
    padding: isPortrait ? 64 : 110,
    /** Pick a value by orientation. */
    pick: <V,>(landscape: V, portrait: V): V => (isPortrait ? portrait : landscape),
  };
};
