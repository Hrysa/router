# Design reference and dependencies

## Yacd-meta

This frontend is a routerd-specific React reimplementation inspired by the local `git-repos/Yacd-meta/` reference at commit `7fe17d8` (package name `yacd`, version `0.6.0`). Credit goes to MetaCubeX and the original yacd contributors. The reference package declares the MIT license.

The reference informs the persistent sidebar/mobile navigation, neutral slate surfaces, blue accents, light/dark themes, overview cards, and traffic visualization. Its React, React Query, Radix dialog, and Feather icon choices also inform this implementation. The routerd UI uses independently written components and routerd API contracts; it does not bundle Yacd-meta's source files, logos, embedded artwork, Clash-specific integrations, or service worker.

The ignored reference checkout is not a dependency and is not needed to build routerd. This notice records design provenance, not a change to routerd's license.

## Runtime dependencies

React, React DOM, TanStack React Query, Radix Dialog, and react-feather are used under their respective MIT licenses. Inter is bundled locally through `@fontsource/inter` under the SIL Open Font License. Dependency versions are recorded in `bun.lock`; upstream license texts are distributed with the installed packages. No font CDN or external dashboard API is required at runtime.
