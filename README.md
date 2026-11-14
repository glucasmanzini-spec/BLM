# Browser Live Messenger (BLM)

A Discord-inspired browser chat application built on Cloudflare.

## Stack
- Cloudflare Workers: API and static asset routing
- Cloudflare D1: users, servers, channels and message history
- Cloudflare Durable Objects: real-time WebSocket rooms
- Vanilla HTML, CSS and JavaScript

## Status
Initial MVP scaffold. See deployment instructions below.

## Setup
1. Install Node.js LTS.
2. Run `npm install`.
3. Authenticate with `npx wrangler login`.
4. Create D1: `npx wrangler d1 create browser-live-messenger`.
5. Put the returned database ID in `wrangler.toml`.
6. Apply schema: `npx wrangler d1 execute browser-live-messenger --file=./schema.sql`.
7. Set a strong secret: `npx wrangler secret put SESSION_SECRET`.
8. Run locally: `npm run dev`.
9. Deploy: `npm run deploy`.

Never commit `SESSION_SECRET` or credentials. Before a public launch, add rate limiting, abuse controls, account recovery, cookie-based sessions, and security review.
