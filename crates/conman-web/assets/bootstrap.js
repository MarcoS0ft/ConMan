const statusNode = document.querySelector("#startup-status");
const detailNode = document.querySelector("#startup-detail");
const reloadButton = document.querySelector("#reload-button");
const BUILD_ID_PATTERN = /^[0-9a-f]{64}$/;
// The package assembler substitutes its content-derived P13.5 identity here
// before the immutable bundle is served. There is intentionally no dev value.
const EXPECTED_BUILD_ID = "__CONMAN_BROWSER_BUILD_ID__";
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_ASSET_HASHES = 256;

function showFailure(message) {
  if (document.documentElement.dataset.browserState === "context-lost") return;
  document.documentElement.dataset.browserState = "failed";
  statusNode.textContent = "Connection Manager could not start.";
  detailNode.textContent = message;
  reloadButton.hidden = false;
}

function showReady() {
  const currentState = document.documentElement.dataset.browserState;
  if (currentState === "failed" || currentState === "context-lost") return;
  document.documentElement.dataset.browserState = "inert-shell";
  statusNode.textContent = "The browser shell is ready.";
  detailNode.textContent =
    "No authenticated gateway application is attached. Workspace actions remain disabled.";
}

function isWinitControlFlow(error) {
  return (
    error instanceof Error &&
    error.message.startsWith("Using exceptions for control flow, don't mind me.")
  );
}

function isJsonContentType(value) {
  if (typeof value !== "string") return false;
  const mediaType = value.split(";", 1)[0].trim();
  return mediaType.toLowerCase() === "application/json";
}

function observeCanvas(canvas) {
  if (canvas.dataset.contextLossObserved === "true") return;
  canvas.dataset.contextLossObserved = "true";
  canvas.inert = true;
  canvas.setAttribute("aria-hidden", "true");
  canvas.addEventListener("webglcontextlost", () => {
    document.documentElement.dataset.browserState = "context-lost";
    statusNode.textContent = "Graphics support was lost.";
    detailNode.textContent =
      "The application has stopped accepting input. Reload to reconnect and restore the display.";
    reloadButton.hidden = false;
  });
}

async function readManifest() {
  const response = await fetch("/api/v1/manifest", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("The gateway build manifest is unavailable.");
  if (!isJsonContentType(response.headers.get("Content-Type"))) {
    throw new Error("The gateway returned the wrong manifest media type.");
  }

  const reader = response.body?.getReader();
  if (!reader) throw new Error("The gateway build manifest has no response body.");
  const chunks = [];
  let totalBytes = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_MANIFEST_BYTES) {
        await reader.cancel();
        throw new Error("The gateway build manifest exceeds its size limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const encoded = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    encoded.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded));
  } catch {
    throw new Error("The gateway build manifest is invalid.");
  }

  if (
    manifest === null ||
    typeof manifest !== "object" ||
    manifest.schema !== 1 ||
    typeof manifest.build_id !== "string" ||
    !BUILD_ID_PATTERN.test(manifest.build_id) ||
    !Array.isArray(manifest.asset_hashes) ||
    manifest.asset_hashes.length > MAX_ASSET_HASHES ||
    manifest.asset_hashes.some((hash) => typeof hash !== "string" || !BUILD_ID_PATTERN.test(hash))
  ) {
    throw new Error("The gateway manifest has an unsupported schema or invalid identity.");
  }
  if (!BUILD_ID_PATTERN.test(EXPECTED_BUILD_ID)) {
    throw new Error("The browser package build identity is unavailable.");
  }
  if (manifest.build_id !== EXPECTED_BUILD_ID) {
    throw new Error("Browser and gateway builds differ; reload the application.");
  }
  return manifest;
}

function requireWebGl2() {
  const probe = document.createElement("canvas");
  const context = probe.getContext("webgl2");
  if (!context) throw new Error("WebGL 2 is unavailable. Enable browser graphics support and reload.");
  context.getExtension("WEBGL_lose_context")?.loseContext();
}

function makeCanvasInert(canvas) {
  observeCanvas(canvas);
}

async function start() {
  reloadButton.addEventListener("click", () => location.reload());

  // This W1 shell has no authenticated application service. Prevent any
  // keyboard event from reaching the Slint canvas until a later authorized
  // application attachment explicitly owns input.
  document.addEventListener(
    "keydown",
    (event) => {
      if (!(event.target instanceof Element) || !event.target.closest("canvas")) return;
      event.preventDefault();
      event.stopImmediatePropagation();
    },
    true,
  );

  const canvasObserver = new MutationObserver(() => {
    document.querySelectorAll("canvas").forEach(makeCanvasInert);
  });
  canvasObserver.observe(document.body, { childList: true, subtree: true });

  try {
    const manifest = await readManifest();
    requireWebGl2();

    // The gateway verifies every exact path against its private route-to-
    // digest map before serving it. WIRE1's digest vector is not treated as a
    // route map by this client.
    const module = await import("/assets/pkg/conman_web.js");
    await module.default();
    module.start(manifest.build_id, manifest.schema);

    document.querySelectorAll("canvas").forEach(makeCanvasInert);
    showReady();
  } catch (error) {
    if (isWinitControlFlow(error)) {
      document.querySelectorAll("canvas").forEach(makeCanvasInert);
      showReady();
    } else {
      showFailure(error instanceof Error ? error.message : "An unexpected startup error occurred.");
    }
  }
}

start();
