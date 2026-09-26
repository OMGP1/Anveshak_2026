# Network Watch — simplified dashboard

This is a separate, simpler version of the existing dashboard. The original `ui/` is preserved. Both views use the same detection API; changing a real replay in either view changes the shared engine.

## Open it

After building, start the API from `SIH2026_prototype`:

```powershell
python -m api.main
```

| View | Address |
| --- | --- |
| Simplified dashboard | http://127.0.0.1:8000/simple/?mock=0 |
| Original dashboard | http://127.0.0.1:8000/?mock=0 |
| Simplified sample mode | http://127.0.0.1:8000/simple/?mock=1 |

To install and build this copy, run these commands from `SIH2026_prototype`:

```powershell
cd ui-simple
npm ci
npm run build
cd ..
python -m api.main
```

If the Python environment has not been set up, first follow the dependency setup in the [project README](../README.md). If port 8000 already serves an older version of the API, restart that process after building so it picks up the `/simple` mount.

The original dashboard has its own build: run `npm ci` and `npm run build` inside `ui/` if needed. Building this copy does not rebuild or modify the original.

## Learn the dashboard

The new **Live monitor** page reads a local passive capture interface and runs all six detector families concurrently. Open **http://127.0.0.1:8000/simple/?mock=0#/live**, choose the mirror/data-diode interface, and select **Start monitoring**. Wireshark/dumpcap and Npcap are required on Windows. See the [live monitoring and NTRO requirement guide](../docs/LIVE_MONITORING_26145.md) for setup, tested rates, and limits.

Alerts are automatically saved to `data/alerts.jsonl` (or the configured `SIH_STATE_DIR`). The **Alerts** page also exports the complete stored history as a JSON array or JSONL. Live and replay are mutually exclusive sessions on the shared engine.

The full guide is **[public/dashboard-guide.md](public/dashboard-guide.md)**. It covers each page, terminology, a presentation script, scores, limitations, and troubleshooting. The website’s **Download guide** link serves this same file; edit it here to update both copies.

## Test with generated traffic

With the API running and any existing capture/replay stopped, run this from `SIH2026_prototype` in a second terminal:

```powershell
python -m tools.attack_lab live --scenario mixed
```

The tool starts its own loopback capture, sends bounded DNS-tunnelling and UDP-scan patterns to its own local sockets, checks the resulting alerts, and stops that capture. Watch **Live monitor** and **Alerts**. Use `--scenario benign` for a zero-alert control. Run `python -m tools.attack_lab offline` to check all six classes from interleaved synthetic captures without transmitting them. Each run saves `report.json`, `alerts.json`, and `alerts.jsonl` under `data/attack-lab/`. See the [attack lab guide](../docs/ATTACK_LAB.md) for all options and interpretation.

## Develop the simplified version

Keep `python -m api.main` running in one terminal. In another terminal, from `SIH2026_prototype`:

```powershell
cd ui-simple
npm run dev
```

Open **http://127.0.0.1:5174/simple/**. The original UI can use port 5173 independently. This copy uses port 5174 with strict port selection. The development server proxies `/api` and `/ws` to port 8000, preserving the request host for the API’s origin checks.

For a frontend-only walkthrough, open **http://127.0.0.1:5174/simple/?mock=1**. No Python server is needed in that mode. All values are simulated and clearly labeled. `?mock=0` switches back to engine data. The preference uses `ui-simple.mock`, separate from the original dashboard’s preference.

## Where to make changes

| File | Purpose |
| --- | --- |
| `src/App.tsx` | Navbar, Overview, Run a demo, Alerts, How it works |
| `src/LivePage.tsx`, `src/useLive.ts` | Live capture controls, interface selection, session metrics and quality |
| `src/styles.css` | Responsive layout, colors, typography, focus states |
| `src/api.ts` | Copied API types, requests, WebSocket connection, sample toggle |
| `src/useEngine.ts` | Copied replay state, live metrics, alert recovery |
| `src/mock.ts` | Browser-only sample data for explanation |
| `src/featureGloss.ts` | Plain-language evidence descriptions |
| `public/dashboard-guide.md` | Downloadable user guide |
| `vite.config.ts` | `/simple/` asset base and development port |
| `../api/main.py` | Mounts this build before the original root dashboard |

Navigation uses URL hashes, so pages can be bookmarked and refreshed without extra server routes. Fonts are bundled locally; the built site does not fetch fonts or scripts from external CDNs. Run `npm run build` to check TypeScript and create the production bundle. This copy deliberately keeps a small set of pages; detailed operations and training controls remain available in the original dashboard.
