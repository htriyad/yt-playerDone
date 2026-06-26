# dist/

This folder contains the pre-built frontend files that get deployed to loveurhum.pages.dev.

## Files
- index.html — main app entry
- gate-admin.html — admin panel (visit /gate-admin)
- gate-enter.html — access gate form shown to new visitors
- gate-closed.html — shown when gate is OFF
- _worker.js — Cloudflare Pages Worker (gate logic + API)
- assets/ — compiled JS and CSS
- favicon.svg, icon-192.png, icon-512.png, manifest.webmanifest

## Deploy
Push to main branch → GitHub Actions auto-deploys to loveurhum.pages.dev
