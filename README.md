# MailAPI

**Your Gmail, as a REST API.** Sign in with Google, get a personal API key, and read / search / send your own mailbox over plain JSON — from any script, cron job, or AI agent. Runs entirely on [Cloudflare Workers](https://workers.cloudflare.com) + Workers KV. No servers, no SDK, no database.

One key reaches **every linked Gmail account at once**, and Gmail's `+tag` / dot aliases become **free disposable addresses** — pass any address as `email` and the API auto-detects it: a linked account returns its whole inbox, an alias returns only mail addressed to that alias.

```
curl -H "Authorization: Bearer $KEY" "https://your-worker.workers.dev/v1/messages?email=you+signup@gmail.com"
```

## Features

- **One key, every linked account** — link multiple Gmail accounts to one key and dashboard; every request names the mailbox it wants with an `email` parameter (or sends `from` it). Multi-key juggling is a mistake of the past — one key, parallel calls, any account.
- **Disposable addresses built in** — Gmail delivers `you+anything@gmail.com` and `y.o.u@gmail.com` to the same inbox. Use them as unlimited temp addresses; the API filters each spelling server-side.
- **Auto-detected addresses** — one parameter handles accounts *and* aliases: plain address = whole inbox, `+tag`/dot variant = only mail addressed to it. No separate alias endpoint, no registration, no per-alias keys.
- **Full mailbox operations** — list, search (plain Gmail query syntax), read parsed text/HTML/attachments, send, labels, modify, trash, threads — plus a raw passthrough to the entire Gmail REST API.
- **Dashboard UI** — sign in with Google, copy your key, browse a live inbox (all accounts, all aliases in one place), link/unlink accounts, rotate or delete everything.
- **Private by construction** — refresh tokens AES-256-GCM encrypted at rest, API keys stored only as SHA-256 hashes, message contents never stored (fetched live from Google and handed straight back), one-click revoke + total data deletion.
- **Edge-fast, near-free** — a single Cloudflare Worker with a content-hashed asset build (immutable caching, auto-busting), memoized static pages, and deduped Google token refreshes. The free Workers plan covers real hobby use.

## Quick start (users)

1. Open your deployed Worker in a browser
2. **Sign in with Google** and approve read/send access
3. Your API key (`gmk_…`) appears on the dashboard — copy it

```bash
KEY="gmk_..."           # from your dashboard
BASE="https://your-worker.workers.dev"

# unread mail
curl -H "Authorization: Bearer $KEY" "$BASE/v1/messages?q=is:unread&maxResults=5"

# a disposable alias inbox (mail sent to you+netflix@ lands in you@, but this shows only that alias)
curl -H "Authorization: Bearer $KEY" "$BASE/v1/messages?email=you%2Bnetflix%40gmail.com"

# a second linked account — same key
curl -H "Authorization: Bearer $KEY" "$BASE/v1/messages?email=me2@gmail.com"

# send (from the key owner, or any linked address/alias with "from")
curl -X POST "$BASE/v1/messages/send" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"to":"friend@example.com","subject":"Hi","text":"sent via my API"}'

# send appearing AS an alias
curl -X POST "$BASE/v1/messages/send" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"from":"you+shop@gmail.com","to":"order@example.com","subject":"Order","text":"..."}'
```

## Deploy your own

### 1. Cloudflare Worker

```bash
git clone https://github.com/nullstacks/mailapi && cd mailapi
npm install

npx wrangler kv namespace create KV     # paste the id into wrangler.toml
npx wrangler login

npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put ENCRYPTION_KEY  # any long random string: openssl rand -hex 32

npx wrangler deploy                     # -> https://mailapi.<your-subdomain>.workers.dev
```

### 2. Google Cloud Console

1. Create/select a project at [console.cloud.google.com](https://console.cloud.google.com)
2. **APIs & Services → Library** → search **Gmail API** → **Enable**
3. **APIs & Services → OAuth consent screen** (Google Auth Platform) → audience **External** → fill app name + support email; add yourself under **Test users** while in Testing mode
4. **APIs & Services → Credentials → Create credentials → OAuth client ID** → type **Web application** → authorized redirect URI:

   ```
   https://mailapi.<your-subdomain>.workers.dev/auth/callback
   ```

5. Copy the client ID / secret into the `wrangler secret put` commands above

Done — open the Worker URL, sign in, take your key.

> **Going fully public?** Gmail scopes are *restricted*: while your app is in Testing, only listed test users can sign in. Unlimited public signups require Google's OAuth verification (homepage + privacy policy on a verified domain, demo video, scope justification, and an annual security assessment for restricted scopes) — or run unverified with Google's 100-user cap. MailAPI ships `/privacy` and `/terms` pages and a homepage to anchor that process.

## Configuration

| Env / Secret | Required | Purpose |
|---|---|---|
| `KV` (binding) | ✅ | one namespace: accounts, keys, sessions, OAuth state |
| `GOOGLE_CLIENT_ID` | ✅ | OAuth client id |
| `GOOGLE_CLIENT_SECRET` | ✅ | OAuth client secret |
| `ENCRYPTION_KEY` | ✅ | long random string; derives the AES-256-GCM key encrypting refresh tokens at rest |
| `SCOPES` (var) | — | override the requested scopes (default `openid email https://www.googleapis.com/auth/gmail.modify`) |

Set a read-only scope for read-only deployments:

```toml
[vars]
SCOPES = "openid email https://www.googleapis.com/auth/gmail.readonly"
```

## API reference

Base URL `https://your-worker.workers.dev` — authenticate with `Authorization: Bearer gmk_…` (or `X-API-Key`). All responses are JSON.

### Choosing the mailbox

Every route accepts an **`email`** selector:

- `?email=you@gmail.com` — that linked account's whole inbox
- `?email=you+netflix@gmail.com` — the account behind `you@`, filtered to mail addressed to that alias
- omitted — the key owner's inbox
- `POST /v1/messages/send` — put `"from": "<address or alias>"` in the JSON body to send as (or from) any linked mailbox/alias
- an address that is neither a linked account nor an alias of one → `404`

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/v1/me` | key owner + linked accounts |
| GET | `/v1/accounts` | all linked accounts + the default |
| GET | `/v1/messages` | list. optional: `email`, `q` (Gmail search), `maxResults` ≤50, `pageToken`, `labelIds`, `ids_only=1` |
| GET | `/v1/messages/:id` | parsed message: `text`, `html`, headers, attachments. `?raw=1` for the full Gmail payload |
| GET | `/v1/messages/:id/attachments/:attId` | binary download (`filename=`, `type=` optional) |
| POST | `/v1/messages/send` | send. body: `{to, from?, cc?, bcc?, subject, text?, html?, attachments?:[{filename, contentType, content(b64)}], threadId?}` |
| POST | `/v1/messages/:id/modify` | `{addLabelIds:[], removeLabelIds:[]}` |
| POST | `/v1/messages/:id/trash` / `/untrash` | trash / restore |
| GET | `/v1/threads/:id` | whole thread, parsed |
| GET | `/v1/labels` | all labels |
| POST | `/v1/key/rotate` | new key; the old one dies |
| DELETE | `/v1/account?email=…` | revoke Google access + delete that account's stored data |
| ANY | `/v1/gmail/*` | raw passthrough to the Gmail REST API |

The API speaks **plain Gmail search syntax** in `q` — everything Gmail's search bar does works:

```bash
# newsletters from last week
curl -H "Authorization: Bearer $KEY" "$BASE/v1/messages?q=category:promotions+newer_than:7d"

# every alias inbox with receipts, across accounts, in parallel
curl -H "Authorization: Bearer $KEY" "$BASE/v1/messages?email=a+receipts@gmail.com" &
curl -H "Authorization: Bearer $KEY" "$BASE/v1/messages?email=b+receipts@gmail.com" &
wait
```

### Response shape

```json
{
  "mailbox": "you+netflix@gmail.com",
  "account": "you@gmail.com",
  "messages": [
    {
      "id": "18f3a9c2b7e1d604",
      "threadId": "18f3a9c2b7e1d604",
      "labels": ["INBOX", "UNREAD"],
      "snippet": "Your verification code is 482913…",
      "from": "Netflix <info@netflix.com>",
      "to": "you+netflix@gmail.com",
      "subject": "Your sign-in code",
      "date": "Mon, 6 Oct 2026 19:04:12 +0000"
    }
  ],
  "nextPageToken": "…",
  "resultSizeEstimate": 1
}
```

`GET /v1/messages/:id` adds `text` (decoded plain-text body), `html` (decoded HTML body), and `attachments` (`id`, `filename`, `mimeType`, `size` — download via the attachments route).

### Errors

| Status | Meaning |
|---|---|
| 401 | bad/missing key, or the Google grant expired (message says *Re-authorize* — sign in again) |
| 404 | unknown route/id — or an `email` that isn't a linked account or alias of one |
| 429 | upstream Gmail quota (per-mailbox; MailAPI adds none of its own) |

## How it works

```
Google OAuth ──▶ per-user accounts in Workers KV ──▶ per-user API key ──▶ Gmail REST API
                    │ refresh tokens AES-GCM at rest      │ SHA-256 hashed only
                    │ auto-refresh, deduped per isolate   │ gmk_ keys
                    └ email:{address} index: every linked account shares the member list
```

- **KV schema** — `user:{sub}` account record (tokens, key hash) · `email:{address}` → linked-account member list · `key:{hash}` → key owner · `sess:{hash}` → dashboard session (7d) · `state:{x}` → OAuth CSRF state (10m)
- **Mailbox resolution** — `resolveMailbox()` takes the `email` param, walks the key's linked group, and returns the account + optional alias filter. Aliases are never registered; they are *recognized*.
- **No alias keys** — one key type. Whoever holds the key controls every account it links; that was equally true for the dashboard, so the model stays honest: accounts are linked to *your* key and removable in one click.
- **Token refresh dedup** — concurrent requests on one isolate share a single Google refresh instead of stampeding the token endpoint.
- **Asset build** — CSS/JS ships with a content hash; browsers cache it `immutable` and any code change busts the URL automatically. Static pages memoize per isolate, so warm requests skip re-rendering entirely.

## Security model

| Layer | Practice |
|---|---|
| Google tokens | AES-256-GCM at rest (key derived from `ENCRYPTION_KEY`), revoked on account delete |
| API keys | stored as SHA-256 hashes only; dashboard shows them via the encrypted copy |
| Sessions | HttpOnly · Secure · SameSite=Lax cookies, 7-day TTL, server-side hash lookup |
| Dashboard mutations | require the `x-requested-with` header (basic CSRF guard) |
| Mail content | never persisted — proxied live from Google |
| Headers | `nosniff`, `referrer-policy`, `frame-deny` on everything |
| Deletion | one click revokes Google + wipes every stored record |

## Self-host or use the hosted instance

The current live deployment (`https://mailapi.pushkarsingh4343.workers.dev`) runs this exact code — its instance is the operator's, so self-host for production use of your own. Cloning + deploying takes about five minutes.

## Project layout

```
mailapi/
├── src/
│   └── index.js      # the entire Worker: OAuth, API, UI, assets (single file by design)
├── wrangler.toml     # Cloudflare config: KV binding, worker name
├── package.json
└── README.md
```

## Roadmap

- [ ] Optional Durable Object rate limiting (per key, per mailbox)
- [ ] Webhooks: push new-mail events via Cloudflare Queues
- [ ] Attachments upload on send (`content` base64 — uploads arrive via `/v1/gmail/*` passthrough today)
- [ ] Multi-user hosting guide (one deployment, many independent users)

## Contributing

Issues and PRs welcome — [nullstacks/mailapi](https://github.com/nullstacks/mailapi). Keep the single-file design; it is the deployment story.

## License

[MIT](LICENSE)
