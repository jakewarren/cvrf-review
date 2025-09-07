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
  const result = await WebAssembly.instantiateStreaming(fetch('main.wasm'), go.importObject);
  await go.run(result.instance);
  output += decoder.decode();
  console.log = origLog;
  console.error = origErr;
  return output;
}

function ansiToHtml(text) {
  const color = {
    '30': 'black', '31': 'red', '32': 'green', '33': 'yellow',
    '34': 'blue', '35': 'magenta', '36': 'cyan', '37': 'white',
    '90': 'gray', '91': 'lightcoral', '92': 'lightgreen', '93': 'khaki',
    '94': 'lightblue', '95': 'plum', '96': 'lightcyan', '97': 'white'
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

document.getElementById('runBtn').addEventListener('click', async () => {
  const product = document.getElementById('product').value;
  const version = document.getElementById('version').value;
  const outputEl = document.getElementById('output');
  outputEl.textContent = 'Running...';
  try {
    const args = ['fortinet', 'affected', '--product', product, '--version', version];
    const out = await runCommand(args);
    outputEl.innerHTML = ansiToHtml(out);
  } catch (e) {
    outputEl.textContent = e.toString();
  }
});
