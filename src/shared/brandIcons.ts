function svgToDataUrl(svg: string): string {
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg.trim())}`;
}

export const BRAND_ICONS = {
  // Official Claude terracotta background + warm cream starburst icon
  claude: svgToDataUrl(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="16" fill="#D97757"/>
      <g transform="translate(32,32)" stroke="#FAF6F0" stroke-width="4.4" stroke-linecap="round">
        <line x1="0" y1="-17" x2="0" y2="17"/>
        <line x1="-17" y1="0" x2="17" y2="0"/>
        <line x1="-12" y1="-12" x2="12" y2="12"/>
        <line x1="-12" y1="12" x2="12" y2="-12"/>
        <line x1="-6.5" y1="-15.5" x2="6.5" y2="15.5"/>
        <line x1="-15.5" y1="-6.5" x2="15.5" y2="6.5"/>
      </g>
    </svg>
  `),

  // Official OpenAI / Codex geometric knot icon
  codex: svgToDataUrl(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="16" fill="#10A37F"/>
      <g transform="translate(32,32)" stroke="#FFFFFF" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round" fill="none">
        <path d="M0 -17 C7 -17 12 -12 12 -5 L12 6"/>
        <path d="M14.7 -8.5 C18.2 -2.4 16.1 5.4 10 8.9 L0.5 14.4"/>
        <path d="M14.7 8.5 C11.2 14.6 3.4 16.7 -2.7 13.2 L-12.2 7.7"/>
        <path d="M0 17 C-7 17 -12 12 -12 5 L-12 -6"/>
        <path d="M-14.7 8.5 C-18.2 2.4 -16.1 -5.4 -10 -8.9 L-0.5 -14.4"/>
        <path d="M-14.7 -8.5 C-11.2 -14.6 -3.4 -16.7 2.7 -13.2 L12.2 -7.7"/>
        <polygon points="0,-6 5.2,-3 5.2,3 0,6 -5.2,3 -5.2,-3" fill="#10A37F"/>
      </g>
    </svg>
  `),

  // Cursor IDE cube icon
  cursor: svgToDataUrl(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="16" fill="#18181B"/>
      <polygon points="32,12 50,22 50,42 32,52 14,42 14,22" stroke="#FFFFFF" stroke-width="3" fill="#27272A"/>
      <polyline points="14,22 32,32 50,22" stroke="#FFFFFF" stroke-width="3"/>
      <line x1="32" y1="32" x2="32" y2="52" stroke="#FFFFFF" stroke-width="3"/>
    </svg>
  `),

  // Perplexity icon
  perplexity: svgToDataUrl(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="16" fill="#1F2937"/>
      <g stroke="#22D3EE" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">
        <line x1="32" y1="13" x2="32" y2="51"/>
        <line x1="15" y1="32" x2="49" y2="32"/>
        <polygon points="20,18 32,30 44,18 44,46 32,34 20,46" fill="none"/>
      </g>
    </svg>
  `),

  // Gemini spark icon
  gemini: svgToDataUrl(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="16" fill="#1E1B4B"/>
      <path d="M32 12 C33 24 40 31 52 32 C40 33 33 40 32 52 C31 40 24 33 12 32 C24 31 31 24 32 12 Z" fill="#818CF8"/>
    </svg>
  `),

  // Domain / HTTP rule icon
  domain: svgToDataUrl(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none">
      <rect width="64" height="64" rx="16" fill="#0F172A"/>
      <circle cx="32" cy="32" r="17" stroke="#38BDF8" stroke-width="3"/>
      <ellipse cx="32" cy="32" rx="8" ry="17" stroke="#38BDF8" stroke-width="2.5"/>
      <line x1="15" y1="32" x2="49" y2="32" stroke="#38BDF8" stroke-width="2.5"/>
    </svg>
  `)
};

