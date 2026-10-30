# Zaventra — messaging platform prototype

This is a **local testing prototype**, not a production-ready public messenger. It provides a responsive web UI, Node/Express server, SQLite storage, phone OTP demo flow, group membership and text messages, bot profile creation, and a server-side Owner overview.

## Requirements
- Node.js 20 or newer
- npm
- For mobile testing, Termux can run Node.js; some native SQLite packages may require build tools on Android. If `better-sqlite3` fails in Termux, use a supported Node environment or replace it with a pure-JS/hosted database adapter.

## Run locally
1. Extract the ZIP.
2. Copy `.env.example` to `.env`.
3. Set a long random `SESSION_SECRET`.
4. Set `OWNER_PHONE` to your verified phone in international format, e.g. `+91...`. Do not put real phone numbers or API secrets in frontend files or public Git repositories.
5. Keep `OTP_DEMO_MODE=true` for local testing only.
6. Install dependencies: `npm install`
7. Start: `npm start`
8. Open `http://localhost:3000`.

## Demo OTP
In demo mode, the server prints the OTP to its terminal. This is **not real SMS verification**. The public API intentionally returns an error if demo mode is disabled until an SMS provider is integrated.

## Important production gaps
Before public hosting or Play Store release, implement and test:
- A real SMS OTP provider, verified phone ownership, resend limits, abuse/fraud controls and account recovery.
- A persistent session store (do not use Express MemoryStore in production), HTTPS, secure cookie configuration and secret rotation.
- Socket.IO session authentication and server-verified room membership. The prototype's socket room subscription is for local demonstration and is not production-safe; do not expose it publicly as-is.
- Group member invitations and role management endpoints, owner recovery, and robust authorization tests.
- Bot runtime, command handlers, rate limits, webhook/worker architecture and optional AI provider integration.
- Block/report, moderation, terms, privacy policy, data retention, user/account deletion, age and child-safety review.
- Message encryption design. This prototype does not implement end-to-end encryption.
- Upload security, malware scanning, file size limits and storage access controls before adding file sharing.
- Backups, monitoring, rate limiting on all sensitive endpoints, database migration and deployment configuration.
- Google Play target API and current Developer Program policies; store approval is never guaranteed.

## Brand name note
A quick web search found a US trademark filing for "ZAVENTRA" in a household/containers category. This does not determine whether the name is available for messaging software in India. Before investing in the brand, search the relevant classes and similar spellings in the official Indian Trade Marks Registry and consider professional advice.
