/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'], darkMode: 'class',
  theme: { extend: {
    colors: { surface: { 950: '#0c1217', 900: '#10191f', 800: '#162129', 700: '#23323b', 600: '#3c4d57' }, accent: { DEFAULT: '#65dbc6', dim: '#45b9a5', glow: '#92ecdb' }, risk: { critical: '#f07782', high: '#eab872', medium: '#d6ce8c', low: '#65dbc6', info: '#94a3b8' }, classify: { sanctioned: '#65dbc6', tolerated: '#eab872', unsanctioned: '#f07782', unknown: '#94a3b8' } },
    fontFamily: { sans: ['"IBM Plex Sans"', '"Segoe UI"', 'sans-serif'], mono: ['"IBM Plex Mono"', 'Consolas', 'monospace'] },
  } }, plugins: [],
}
