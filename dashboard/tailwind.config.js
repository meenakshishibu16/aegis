/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#0e0f10", 900: "#1a1a19", 800: "#262624", 700: "#383835", 400: "#9b9a92", 300: "#c3c2b7", 100: "#f0efec" },
        good: "#0ca30c",
        warn: "#fab219",
        crit: "#d03b3b",
        accent: "#3987e5",
      },
      fontFamily: { mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"] },
    },
  },
  plugins: [],
};
