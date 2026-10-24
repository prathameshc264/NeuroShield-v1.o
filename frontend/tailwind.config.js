/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'neuro-dark': '#0f172a',
        'neuro-card': '#1e293b',
        'neuro-accent': '#38bdf8',
        'neuro-critical': '#ef4444',
        'neuro-high': '#f97316',
        'neuro-medium': '#eab308',
        'neuro-low': '#22c55e',
      }
    },
  },
  plugins: [],
}
