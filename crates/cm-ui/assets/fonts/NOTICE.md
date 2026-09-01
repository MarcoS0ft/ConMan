# Bundled font assets — redistribution licenses

These fonts are compiled into `cm-ui` via `include_bytes!` (see
`src/terminal_renderer.rs`) and rendered by the software glyph atlas. All are
redistributable under permissive font licenses compatible with ConMan's
royalty-free and proprietary-compatible posture (**no GPL/LGPL**).

Source: Nerd Fonts release **v3.4.0** (https://github.com/ryanoasis/nerd-fonts),
downloaded 2026-06-27.

## JetBrains Mono Nerd Font Mono — base font (regular / bold / italic / bold-italic)

- Files: `JetBrainsMonoNerdFontMono-{Regular,Bold,Italic,BoldItalic}.ttf`
- Upstream typeface: JetBrains Mono **v2.304** (patched with Nerd Font glyphs).
- **License: SIL Open Font License, Version 1.1** — see `JetBrainsMono-OFL.txt`.
  Copyright 2020 The JetBrains Mono Project Authors
  (https://github.com/JetBrains/JetBrainsMono).

  > JetBrains Mono 1.x used Apache-2.0. **JetBrains relicensed JetBrains Mono
  > to SIL OFL-1.1 starting with the 2.x
  > series**, and the Nerd Fonts v3.4.0 archive ships the OFL-1.1 (v2.304)
  > build. OFL-1.1 is a permissive font license that explicitly permits bundling
  > and redistribution inside applications (including commercial/proprietary
  > software); the only material constraints are (a) the font may not be sold on
  > its own, (b) the license/copyright must travel with it (this file), and (c)
  > the OFL Reserved-Font-Name clause — which only restricts *modified* copies
  > from reusing the reserved name. We redistribute the font **verbatim**
  > (unmodified) and ship the license, so OFL-1.1 imposes no problem. It is
  > **not** GPL/LGPL.

## Symbols Nerd Font Mono — universal icon fallback

- File: `SymbolsNerdFontMono-Regular.ttf`
- **License: MIT** — see `SymbolsNerdFont-LICENSE-MIT.txt`.
  Copyright (c) 2014 Ryan L McIntyre (the Nerd Fonts project).
- Note: the *aggregated icon glyphs* inside the Nerd Fonts symbol set originate
  from multiple upstream icon projects (e.g. Font Awesome, Material Design Icons,
  Devicons, Octicons, Weather Icons, Powerline), each under its own permissive
  license (mixes of MIT, SIL OFL-1.1, and CC-BY-4.0). The Nerd Fonts
  distribution wrapper is MIT. None are copyleft/GPL.

## Why these two

The renderer's atlas looks up **base font → Symbols Nerd Font Mono**, so any
base font (including a user-selected font) gains
Nerd Font icon coverage from the fallback. JetBrains Mono Nerd Font is itself
already patched, so with the default bundle the base resolves icons directly;
the symbols font is the safety net for non-patched bases.
