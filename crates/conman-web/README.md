# conman-web W1 shell

This crate is the inert Slint WebAssembly composition shell only. It has no
login, gateway transport, application service, workspace seed data, or active
UI2 controller. The HTML startup shield remains over the Slint canvas and
blocks pointer and keyboard input until an authorized application attachment
is implemented. Winit binds the single HTML-owned `#canvas` render target;
the W1 shield keeps that canvas inert and hidden from assistive technology.

The static files are `assets/index.html`, `assets/bootstrap.js`, and
`assets/bootstrap.css`. The canvas uses viewport-owned CSS dimensions with
`!important` so Winit’s inline pixel sizing cannot freeze it at the initial
window size. Winit observes the canvas size and updates the Slint/WebGL backing
surface when the browser viewport changes; the startup shield remains layered
over the canvas. The package root is `/`; wasm-bindgen's `--target web`
output is served below `/assets/pkg/`, including only exact snippet import
paths present in its generated JS. The gateway package route manifest maps
each exact path to a digest and MIME type and verifies bytes before serving.
Gateway code and root-owned packaging/build-stamp scripts are outside this
crate.

The required `CONMAN_BROWSER_BUILD_ID` compile-time variable has no fallback.
The package assembler substitutes that same content-derived P13.5 digest for
the exact `__CONMAN_BROWSER_BUILD_ID__` token in `assets/bootstrap.js`; startup
rejects a malformed or mismatched identity before importing the WASM module.
It must be the coordinator-generated digest for operational builds. Tests may
substitute an explicitly test-only valid digest in a temporary fixture; that
does not authorize packaging such an artifact.
