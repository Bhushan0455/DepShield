/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0A0A14', // Deep Void
        primary: '#7B61FF',    // Plasma
        ghost: '#F0EFF4',      // Ghost
        surface: '#18181B',    // Graphite
      },
      fontFamily: {
        head: ['Sora', 'sans-serif'],
        drama: ['Instrument Serif', 'serif'],
        mono: ['Fira Code', 'monospace'],
        body: ['Sora', 'sans-serif'],
      },
      borderRadius: {
        '4xl': '2rem',
        '5xl': '2.5rem',
        '6xl': '3rem',
      },
    },
  },
  plugins: [],
}
