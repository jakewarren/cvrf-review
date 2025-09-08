async function runCommand(args) {
  const go = new Go();
  go.argv = ['cvrf-review', ...args];
  let output = '';
  const decoder = new TextDecoder('utf-8');
  const writer = {
    write: (buf) => {
      output += decoder.decode(buf, { stream: true });
    }
  };
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a) => { output += a.join(' ') + '\n'; };
  console.error = (...a) => { output += a.join(' ') + '\n'; };
  go.stdout = writer;
  go.stderr = writer;

  // Standard Go WASM bootstrap with MIME fallback
  const wasmURL = 'main.wasm?ts=' + Date.now(); // cache-bust to avoid stale mismatches
  let instance;
  try {
    if (WebAssembly.instantiateStreaming) {
      const resp = fetch(wasmURL);
      const result = await WebAssembly.instantiateStreaming(resp, go.importObject);
      instance = result.instance;
    } else {
      const resp = await fetch(wasmURL);
      const bytes = await resp.arrayBuffer();
      const result = await WebAssembly.instantiate(bytes, go.importObject);
      instance = result.instance;
    }
  } catch (e) {
    // Fallback when server doesn't send application/wasm or streaming fails
    const resp = await fetch(wasmURL);
    const bytes = await resp.arrayBuffer();
    const result = await WebAssembly.instantiate(bytes, go.importObject);
    instance = result.instance;
  }

  await go.run(instance);
  output += decoder.decode();
  console.log = origLog;
  console.error = origErr;
  return output || '\nNo matching advisories found. Try different inputs or --json.';
}

function ansiToHtml(text) {
  // Map ANSI SGR color codes to CSS variables for high contrast in light/dark themes
  const color = {
    '30': 'var(--ansi-black)',
    '31': 'var(--ansi-red)',
    '32': 'var(--ansi-green)',
    '33': 'var(--ansi-yellow)',
    '34': 'var(--ansi-blue)',
    '35': 'var(--ansi-magenta)',
    '36': 'var(--ansi-cyan)',
    '37': 'var(--ansi-white)',
    '90': 'var(--ansi-bright-black)',
    '91': 'var(--ansi-bright-red)',
    '92': 'var(--ansi-bright-green)',
    '93': 'var(--ansi-bright-yellow)',
    '94': 'var(--ansi-bright-blue)',
    '95': 'var(--ansi-bright-magenta)',
    '96': 'var(--ansi-bright-cyan)',
    '97': 'var(--ansi-bright-white)'
  };
  const esc = s => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let res = '';
  let stack = [];
  const re = /\x1b\[([0-9;]+)m/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    res += esc(text.slice(last, m.index));
    const codes = m[1].split(';');
    codes.forEach(code => {
      if (code === '0') {
        while (stack.length) res += stack.pop();
      } else if (code === '1') {
        res += '<span style="font-weight:bold">';
        stack.push('</span>');
      } else if (color[code]) {
        res += `<span style="color:${color[code]}">`;
        stack.push('</span>');
      }
    });
    last = re.lastIndex;
  }
  res += esc(text.slice(last));
  while (stack.length) res += stack.pop();
  return res;
}

// Theme toggle: allow overriding prefers-color-scheme with a button
const THEME_KEY = 'cvrf-theme';
function setTheme(theme) {
  document.body.classList.remove('theme-light', 'theme-dark');
  if (theme === 'light') document.body.classList.add('theme-light');
  if (theme === 'dark') document.body.classList.add('theme-dark');
  const btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = theme === 'dark' ? '☀️ Light' : '🌙 Dark';
}

(() => {
  const saved = localStorage.getItem(THEME_KEY);
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const initial = saved || (prefersDark ? 'dark' : 'light');
  setTheme(initial);
  const btn = document.getElementById('themeToggle');
  btn?.addEventListener('click', () => {
    const current = document.body.classList.contains('theme-dark') ? 'dark' : 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(THEME_KEY, next);
    setTheme(next);
  });
})();

fetch('docs/products.json')
  .then(r => r.json())
  .then(products => {
    const list = document.getElementById('products');
    products.forEach(p => {
      const option = document.createElement('option');
      option.value = p;
      list.appendChild(option);
    });
  });

// Severity preset logic: update min/max when a preset is chosen
const severityPresets = {
  critical: [9.0, 10.0],
  high: [7.0, 8.9],
  medium: [4.0, 6.9],
  low: [0.1, 3.9],
};

const severityEl = document.getElementById('severity');
const minEl = document.getElementById('minCvss');
const maxEl = document.getElementById('maxCvss');

severityEl?.addEventListener('change', () => {
  const v = severityEl.value;
  if (severityPresets[v]) {
    const [min, max] = severityPresets[v];
    minEl.value = String(min);
    maxEl.value = String(max);
  }
});

document.getElementById('runBtn').addEventListener('click', async () => {
  const product = document.getElementById('product').value;
  const version = document.getElementById('version').value;
  const outputEl = document.getElementById('output');
  outputEl.textContent = 'Running...';
  try {
    const args = ['fortinet', 'affected', '--product', product, '--version', version];

    // Decide whether to pass --severity or explicit min/max
    const sev = severityEl?.value || '';
    const minVal = parseFloat(minEl?.value ?? '');
    const maxVal = parseFloat(maxEl?.value ?? '');
    const preset = severityPresets[sev];
    const approxEq = (a, b) => Math.abs(a - b) < 1e-6;

    if (sev && preset && approxEq(minVal, preset[0]) && approxEq(maxVal, preset[1])) {
      args.push('--severity', sev);
    } else {
      if (!Number.isNaN(minVal)) args.push('--min-cvss-score', String(minVal));
      if (!Number.isNaN(maxVal)) args.push('--max-cvss-score', String(maxVal));
    }

    const out = await runCommand(args);
    outputEl.innerHTML = ansiToHtml(out);
  } catch (e) {
    outputEl.textContent = e.toString();
  }
});
