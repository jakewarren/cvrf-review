const go = new Go();

async function loadWasm() {
  const result = await WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject);
  go.run(result.instance);
}

async function init() {
  await loadWasm();
  const resp = await fetch("cvrf/manifest.json");
  const manifest = await resp.json();
  const select = document.getElementById("advisory");
  manifest.forEach(path => {
    const opt = document.createElement("option");
    opt.value = path;
    opt.textContent = path;
    select.appendChild(opt);
  });
  document.getElementById("loadBtn").addEventListener("click", async () => {
    const path = select.value;
    const dataResp = await fetch("cvrf/" + path);
    const text = await dataResp.text();
    const result = window.parseCVRF(text);
    document.getElementById("output").textContent = JSON.stringify(result, null, 2);
  });
}

init();
