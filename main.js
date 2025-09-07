async function runCommand(cmd) {
  const go = new Go();
  const args = cmd.trim().split(/\s+/);
  go.argv = ['cvrf-review', ...args];
  let output = '';
  const decoder = new TextDecoder('utf-8');
  const writer = {
    write: (buf) => {
      output += decoder.decode(buf);
    }
  };
  go.stdout = writer;
  go.stderr = writer;
  const result = await WebAssembly.instantiateStreaming(fetch('main.wasm'), go.importObject);
  await go.run(result.instance);
  return output;
}

document.getElementById('runBtn').addEventListener('click', async () => {
  const cmd = document.getElementById('command').value;
  document.getElementById('output').textContent = 'Running...';
  try {
    const out = await runCommand(cmd);
    document.getElementById('output').textContent = out;
  } catch (e) {
    document.getElementById('output').textContent = e.toString();
  }
});
