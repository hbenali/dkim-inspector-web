# DKIM Inspector

A single-page DKIM record inspector and validator, live at [dkim.hbenali.ovh](https://dkim.hbenali.ovh). Lookups go straight from the browser to Google DNS over HTTPS. No backend, no build step.

## Styling

Dark editorial design shared with hbenali.ovh. `site.css` holds all colours as tokens in `:root` (dark) with one `prefers-color-scheme: light` override, so the site follows the system setting with no toggle. Fonts are self-hosted in `fonts/` (OFL, see `fonts/README.md`). A strict CSP is set in the pages: scripts and styles are `'self'` only, and the only external origin is `https://dns.google`.

## Running locally

```bash
python3 -m http.server 8080
```
