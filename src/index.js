// MailAPI — your Gmail as a REST API · Cloudflare Worker
// Bindings expected: KV, ENCRYPTION_KEY, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, (optional) SCOPES

const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE = "https://oauth2.googleapis.com/revoke";
const GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me";
const DEFAULT_SCOPES = "openid email https://www.googleapis.com/auth/gmail.modify";
const SESSION_TTL = 604800;

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ────────────────────────────── responses ────────────────────────────── */

const SEC = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "x-frame-options": "DENY",
};
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...SEC, ...headers },
  });
const err = (status, message) => json({ error: message }, status);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/* ───────────────────────────── crypto / ids ───────────────────────────── */

function bytesToB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 32768));
  return btoa(s);
}
const toB64u = (bytes) => bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function fromB64u(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
const randomToken = (n = 32) => toB64u(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s) => toB64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));

// Derive the AES key once per isolate instead of on every encrypt/decrypt.
let keyPromise;
const aesKey = (env) =>
  (keyPromise ??= crypto.subtle
    .digest("SHA-256", enc.encode(env.ENCRYPTION_KEY))
    .then((raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"])));

async function encrypt(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), enc.encode(text));
  return `${toB64u(iv)}.${toB64u(new Uint8Array(ct))}`;
}
async function decrypt(env, blob) {
  const [iv, ct] = blob.split(".");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64u(iv) }, await aesKey(env), fromB64u(ct));
  return dec.decode(pt);
}

/* ─────────────────────────── address helpers ─────────────────────────── */

function localPart(addr) {
  const s = String(addr || "");
  const lt = s.lastIndexOf("<");
  return ((lt === -1 ? s : s.slice(lt + 1)).replace(/[<>]/g, "").split("@")[0] || "").trim();
}
function domainPart(addr) {
  const s = String(addr || "");
  const at = s.lastIndexOf("@");
  return at === -1 ? "" : s.slice(at + 1).trim().toLowerCase();
}
function canonicalLocal(local) {
  const plus = String(local).indexOf("+");
  return (plus === -1 ? local : local.slice(0, plus)).replace(/\./g, "").toLowerCase();
}
function sameInbox(alias, rootEmail) {
  const a = canonicalLocal(localPart(alias));
  return !!domainPart(alias) && domainPart(alias) === domainPart(rootEmail) && !!a && a === canonicalLocal(localPart(rootEmail));
}
const aliasSearchQuery = (alias) => `to:${String(alias).trim()}`;
const aliasEmail = (alias, rootEmail) => `${localPart(alias)}@${domainPart(rootEmail)}`;

const headerMap = (mm) => Object.fromEntries((mm.payload?.headers || []).map((x) => [x.name.toLowerCase(), x.value]));

/* ───────────────────────────────── storage ───────────────────────────────── */

const getUser = (env, sub) => env.KV.get(`user:${sub}`, "json");
const putUser = (env, user) => env.KV.put(`user:${user.sub}`, JSON.stringify(user));
const emailIndex = async (env, email) => {
  const rec = await env.KV.get(`email:${String(email).toLowerCase()}`);
  return rec ? rec.split(",").map((s) => s.trim()).filter(Boolean) : [];
};
const setEmailIndex = (env, email, subs) =>
  env.KV.put(`email:${String(email).toLowerCase()}`, [...new Set(subs)].join(","));

// Every linked account keeps the same member list, so switching accounts never loses the others.
async function syncIndex(env, subs) {
  const users = (await Promise.all([...new Set(subs)].map((s) => getUser(env, s)))).filter(Boolean);
  const live = users.map((u) => u.sub);
  await Promise.all(users.map((u) => setEmailIndex(env, u.email, live)));
}
async function linkedUsers(env, user) {
  const subs = await emailIndex(env, user.email);
  const users = (await Promise.all(subs.map((s) => getUser(env, s)))).filter(Boolean);
  return users.length ? users : [user];
}

async function issueApiKey(env, user) {
  if (user.key_hash) await env.KV.delete(`key:${user.key_hash}`);
  const key = `gmk_${randomToken(32)}`;
  user.key_hash = await sha256(key);
  user.api_key_enc = await encrypt(env, key);
  await Promise.all([env.KV.put(`key:${user.key_hash}`, user.sub), putUser(env, user)]);
  return key;
}

// Read the stored API-key copy; if it was written under a different ENCRYPTION_KEY
// (key rotation, namespace migration) it cannot authenticate — re-issue instead of failing.
async function readApiKey(env, user) {
  try {
    return await decrypt(env, user.api_key_enc);
  } catch {
    return issueApiKey(env, user);
  }
}

async function resolveKeyPrincipal(req, env) {
  const h = req.headers.get("authorization") || "";
  const key = h.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : req.headers.get("x-api-key");
  if (!key) return null;
  const sub = await env.KV.get(`key:${await sha256(key)}`);
  const user = sub && (await getUser(env, sub));
  return user ? { user } : null;
}

async function revokeGoogle(env, u) {
  try {
    await fetch(`${GOOGLE_REVOKE}?token=${encodeURIComponent(await decrypt(env, u.refresh_token))}`, { method: "POST" });
  } catch {}
}
async function cleanupUser(env, u) {
  if (!u) return;
  await Promise.all([
    u.key_hash && env.KV.delete(`key:${u.key_hash}`),
    ...(u.alias_keys || []).map((ak) => env.KV.delete(`aliaskey:${ak.kh}`)), // legacy alias-key records, if any
    env.KV.delete(`user:${u.sub}`),
  ]);
}
// Revoke at Google, wipe the record, and repair the remaining group. Returns the remaining subs.
async function deleteAccount(env, user) {
  const subs = await emailIndex(env, user.email);
  await revokeGoogle(env, user);
  await cleanupUser(env, user);
  await env.KV.delete(`email:${user.email.toLowerCase()}`);
  const rest = subs.filter((s) => s !== user.sub);
  await syncIndex(env, rest);
  return rest;
}

/* ───────────────────────────────── google ───────────────────────────────── */

// Concurrent callers on one isolate share a single refresh instead of each hitting Google.
const refreshing = new Map();
async function refreshToken(env, user) {
  const res = await fetch(GOOGLE_TOKEN, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: await decrypt(env, user.refresh_token),
      grant_type: "refresh_token",
    }),
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error_description || data.error), { reauth: true });
  user.access_token = data.access_token;
  user.expires_at = Date.now() + data.expires_in * 1e3;
  await putUser(env, user);
  return user.access_token;
}
function getAccessToken(env, user) {
  if (user.access_token && user.expires_at > Date.now() + 6e4) return user.access_token;
  let p = refreshing.get(user.sub);
  if (!p) {
    p = refreshToken(env, user).finally(() => refreshing.delete(user.sub));
    refreshing.set(user.sub, p);
  }
  return p;
}
async function gmail(env, user, path, init = {}) {
  const token = await getAccessToken(env, user);
  return fetch(`${GMAIL}${path}`, { ...init, headers: { ...(init.headers || {}), authorization: `Bearer ${token}` } });
}
async function gmailJson(env, user, path, init) {
  const res = await gmail(env, user, path, init);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error?.message || "Gmail error"), { status: res.status });
  return data;
}

/* ───────────────────────────────── session ───────────────────────────────── */

const getSid = (req) => (req.headers.get("cookie") || "").match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
async function session(req, env) {
  const sid = getSid(req);
  if (!sid) return null;
  const sub = await env.KV.get(`sess:${await sha256(sid)}`);
  return sub ? getUser(env, sub) : null;
}
const COOKIE_FLAGS = "Path=/; Secure; SameSite=Lax";
function sessionHeaders(sid) {
  const h = new Headers();
  // `sid` is HttpOnly; `mailapi` is a harmless presence flag so cached pages can show the right nav.
  h.append("set-cookie", `sid=${sid}; ${COOKIE_FLAGS}; HttpOnly; Max-Age=${SESSION_TTL}`);
  h.append("set-cookie", `mailapi=1; ${COOKIE_FLAGS}; Max-Age=${SESSION_TTL}`);
  return h;
}
function clearedHeaders() {
  const h = new Headers();
  h.append("set-cookie", `sid=; ${COOKIE_FLAGS}; HttpOnly; Max-Age=0`);
  h.append("set-cookie", `mailapi=; ${COOKIE_FLAGS}; Max-Age=0`);
  return h;
}

async function login(req, url, env) {
  const linkMode = url.searchParams.get("link") === "1" && !!(await session(req, env));
  const state = (linkMode ? "ln" : "lo") + randomToken(14);
  await env.KV.put(`state:${state}`, "1", { expirationTtl: 600 });
  const p = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: `${url.origin}/auth/callback`,
    response_type: "code",
    scope: env.SCOPES || DEFAULT_SCOPES,
    access_type: "offline",
    prompt: "consent", // always: guarantees a refresh token for the account in play
    state,
  });
  return Response.redirect(`${GOOGLE_AUTH}?${p}`, 302);
}

async function callback(req, url, env) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state") || "";
  if (url.searchParams.get("error"))
    return errPage("Authorization failed", `Google said: ${url.searchParams.get("error")} ("access_denied" means the permission was declined)`);
  if (!code || !state || !(await env.KV.get(`state:${state}`)))
    return errPage("Invalid or expired state", "Start again from the sign-in button.");
  await env.KV.delete(`state:${state}`);
  const linkMode = state.startsWith("ln");
  const sessUser = linkMode ? await session(req, env) : null;
  if (linkMode && !sessUser) return errPage("Session expired", "Sign in again, then use Link another account.");

  const res = await fetch(GOOGLE_TOKEN, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${url.origin}/auth/callback`,
      grant_type: "authorization_code",
    }),
  });
  const tokens = await res.json();
  if (!res.ok) return errPage("Token exchange failed", tokens.error_description || tokens.error || "unknown");
  const claims = JSON.parse(dec.decode(fromB64u(tokens.id_token.split(".")[1])));
  const email = (claims.email || "").toLowerCase();
  const existing = await getUser(env, claims.sub);
  if (!tokens.refresh_token && !existing)
    return errPage("No refresh token returned", "Open myaccount.google.com/permissions, remove MailAPI, then sign in again.");

  const expires_at = Date.now() + tokens.expires_in * 1e3;
  let user,
    flash = "",
    sessSub = null;
  if (linkMode && email !== sessUser.email.toLowerCase()) {
    user = {
      ...(existing || { created_at: Date.now() }),
      sub: claims.sub,
      email,
      access_token: tokens.access_token,
      expires_at,
      refresh_token: tokens.refresh_token ? await encrypt(env, tokens.refresh_token) : existing.refresh_token,
    };
    if (!user.api_key_enc) await issueApiKey(env, user);
    else await putUser(env, user);
    const [a, b] = await Promise.all([emailIndex(env, email), emailIndex(env, sessUser.email)]);
    await syncIndex(env, [claims.sub, sessUser.sub, ...a, ...b]);
    flash = `linked=${encodeURIComponent(email)}`;
    sessSub = sessUser.sub; // linking adds an account; it never replaces the one you're signed in with
  } else if (existing && email === existing.email.toLowerCase()) {
    user = { ...existing, email, access_token: tokens.access_token, expires_at };
    if (tokens.refresh_token) user.refresh_token = await encrypt(env, tokens.refresh_token);
    await putUser(env, user);
    const idx = await emailIndex(env, email);
    await setEmailIndex(env, email, [claims.sub, ...idx.filter((s) => s !== claims.sub)]);
  } else {
    const oldIndex = existing ? await emailIndex(env, existing.email) : [];
    const oldSub = existing?.sub;
    if (existing) await cleanupUser(env, existing);
    user = { sub: claims.sub, email, created_at: existing?.created_at || Date.now(), access_token: tokens.access_token, expires_at };
    user.refresh_token = await encrypt(env, tokens.refresh_token || (existing && (await decrypt(env, existing.refresh_token))));
    await issueApiKey(env, user);
    await syncIndex(env, [claims.sub, ...oldIndex.filter((s) => s !== oldSub)]);
    flash = "relinked=1";
  }

  const sid = randomToken(32);
  await env.KV.put(`sess:${await sha256(sid)}`, sessSub || user.sub, { expirationTtl: SESSION_TTL });
  const headers = sessionHeaders(sid);
  headers.set("location", `/dashboard${flash ? "?" + flash : ""}`);
  return new Response(null, { status: 302, headers });
}

/* ─────────────────────────────── gmail parsing ─────────────────────────────── */

function parseMessage(m) {
  const headers = headerMap(m);
  const out = { text: "", html: "", attachments: [] };
  (function walk(part) {
    if (!part) return;
    if (part.filename && part.body?.attachmentId) {
      out.attachments.push({ id: part.body.attachmentId, filename: part.filename, mimeType: part.mimeType, size: part.body.size });
    } else if (part.body?.data && part.mimeType === "text/plain") out.text += dec.decode(fromB64u(part.body.data));
    else if (part.body?.data && part.mimeType === "text/html") out.html += dec.decode(fromB64u(part.body.data));
    (part.parts || []).forEach(walk);
  })(m.payload);
  return {
    id: m.id,
    threadId: m.threadId,
    labels: m.labelIds,
    snippet: m.snippet,
    date: headers.date,
    from: headers.from,
    to: headers.to,
    cc: headers.cc,
    subject: headers.subject,
    messageId: headers["message-id"],
    ...out,
  };
}

const wrap76 = (b64) => b64.replace(/\s/g, "").replace(/.{76}/g, "$&\r\n");
const textPart = (type, content) =>
  `Content-Type: ${type}; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${wrap76(bytesToB64(enc.encode(content)))}`;
const multipart = (sub, parts) => {
  const b = `b_${crypto.randomUUID()}`;
  return { ct: `multipart/${sub}; boundary="${b}"`, body: parts.map((p) => `--${b}\r\n${p}`).join("\r\n") + `\r\n--${b}--` };
};
const encodeWord = (s) => (/^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${bytesToB64(enc.encode(s))}?=`);
// Header values must never carry CR/LF (prevents header injection through to/subject/etc).
const clean = (v) => String(v ?? "").replace(/[\r\n]+/g, " ");

function buildMime({ from, to, cc, bcc, subject, text, html: htmlBody, inReplyTo, references, attachments = [] }) {
  const list = (v) => [].concat(v || []).map(clean).join(", ");
  const head = [`From: ${clean(from)}`, `To: ${list(to)}`];
  if (cc) head.push(`Cc: ${list(cc)}`);
  if (bcc) head.push(`Bcc: ${list(bcc)}`);
  head.push(`Subject: ${encodeWord(clean(subject))}`, "MIME-Version: 1.0");
  if (inReplyTo) head.push(`In-Reply-To: ${clean(inReplyTo)}`, `References: ${clean(references || inReplyTo)}`);
  let main;
  if (text && htmlBody) {
    const alt = multipart("alternative", [textPart("text/plain", text), textPart("text/html", htmlBody)]);
    main = `Content-Type: ${alt.ct}\r\n\r\n${alt.body}`;
  } else main = textPart(htmlBody ? "text/html" : "text/plain", htmlBody || text || "");
  if (attachments.length) {
    const parts = [
      main,
      ...attachments.map(
        (a) =>
          `Content-Type: ${clean(a.contentType || "application/octet-stream")}; name="${clean(a.filename).replace(/"/g, "")}"\r\nContent-Disposition: attachment; filename="${clean(a.filename).replace(/"/g, "")}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${wrap76(a.content)}`
      ),
    ];
    const mixed = multipart("mixed", parts);
    main = `Content-Type: ${mixed.ct}\r\n\r\n${mixed.body}`;
  }
  return enc.encode(head.join("\r\n") + "\r\n" + main);
}

/* ───────────────────────────────── REST API ───────────────────────────────── */

const META_HEADERS = ["From", "To", "Cc", "Subject", "Date", "Delivered-To"];
const META_QS = META_HEADERS.map((h) => `metadataHeaders=${h}`).join("&");

const emailOf = (s) => {
  s = String(s || "").trim().toLowerCase();
  return (s.match(/<([^>]+)>/)?.[1] || s).trim();
};

// Auto-detect the mailbox from one address, across every linked account:
//   you@gmail.com      -> that account's whole inbox
//   you+tag@gmail.com  -> same account, only mail addressed to that variant (+tag or dots)
// No address -> the key's own account. Accounts never "switch": each request picks its own.
async function resolveMailbox(env, user, address) {
  const addr = emailOf(address);
  if (!addr || addr === user.email.toLowerCase()) return { account: user, alias: null };
  const members = await linkedUsers(env, user);
  const exact = members.find((u) => u.email.toLowerCase() === addr);
  if (exact) return { account: exact, alias: null };
  const owner = members.find((u) => sameInbox(addr, u.email));
  if (owner) return { account: owner, alias: aliasEmail(addr, owner.email) };
  throw Object.assign(new Error(`${addr} is not a linked account or an alias of one`), { status: 404 });
}

async function api(req, env, url, principal) {
  const user = principal.user;
  const path = url.pathname.replace(/^\/v1/, "");
  const method = req.method;
  const q = url.searchParams;
  let m;

  if (path === "/me" && method === "GET") {
    const linked = (await linkedUsers(env, user)).map((u) => u.email);
    return json({ email: user.email, linked_accounts: linked, created_at: new Date(user.created_at || Date.now()).toISOString() });
  }

  if (path === "/accounts" && method === "GET") {
    const accounts = (await linkedUsers(env, user)).map((u) => ({ email: u.email }));
    return json({ accounts, default: user.email });
  }

  if (path === "/key/rotate" && method === "POST") return json({ api_key: await issueApiKey(env, user) });

  // Everything below works on one mailbox, picked per request by `email` (query, or `from`/`email` in the send body).
  const isSend = path === "/messages/send" && method === "POST";
  let body = {};
  if (isSend) {
    try { body = await req.json(); } catch { return err(400, "Body must be JSON"); }
    if (!body.to) return err(400, "`to` is required");
  }
  const requested = isSend ? body.from || body.email : q.get("email");

  if (path === "/account" && method === "DELETE") {
    if (!requested) return err(400, "`email` is required to say which account to delete");
    const { account, alias } = await resolveMailbox(env, user, requested);
    if (alias) return err(400, "Give the account address itself, not an alias");
    await deleteAccount(env, account);
    return json({ deleted: account.email });
  }

  const { account, alias } = await resolveMailbox(env, user, requested);

  if (path === "/labels" && method === "GET") return json(await gmailJson(env, account, "/labels"));

  if (path === "/messages" && method === "GET") {
    let query = q.get("q") || "";
    if (alias) query = `(${query ? query + ") AND (" : ""}${aliasSearchQuery(alias)})`;

    const p = new URLSearchParams();
    if (query) p.set("q", query);
    for (const k of ["pageToken", "includeSpamTrash"]) if (q.get(k)) p.set(k, q.get(k));
    p.set("maxResults", Math.min(+q.get("maxResults") || 10, 50));
    p.set("fields", "messages(id),nextPageToken,resultSizeEstimate");
    q.getAll("labelIds").forEach((l) => p.append("labelIds", l));
    await getAccessToken(env, account); // refresh once up front, not once per message below
    const list = await gmailJson(env, account, `/messages?${p}`);
    if (q.get("ids_only")) return json(list);

    const fields = encodeURIComponent("id,threadId,labelIds,snippet,payload/headers");
    const messages = await Promise.all(
      (list.messages || []).map(async ({ id }) => {
        const mm = await gmailJson(env, account, `/messages/${id}?format=metadata&${META_QS}&fields=${fields}`);
        const h = headerMap(mm);
        return { id, threadId: mm.threadId, labels: mm.labelIds, snippet: mm.snippet, from: h.from, to: h.to, subject: h.subject, date: h.date };
      })
    );
    return json({
      mailbox: alias || account.email,
      account: account.email,
      messages,
      nextPageToken: list.nextPageToken,
      resultSizeEstimate: list.resultSizeEstimate,
    });
  }

  if (isSend) {
    const from = alias || account.email;
    const raw = toB64u(buildMime({ ...body, from }));
    return json(
      await gmailJson(env, account, "/messages/send", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ raw, threadId: body.threadId }),
      })
    );
  }

  if ((m = path.match(/^\/messages\/([\w-]+)\/attachments\/([\w-]+)$/)) && method === "GET") {
    const a = await gmailJson(env, account, `/messages/${m[1]}/attachments/${m[2]}`);
    const filename = (q.get("filename") || "file").replace(/["\r\n]/g, "");
    return new Response(fromB64u(a.data), {
      headers: { "content-type": q.get("type") || "application/octet-stream", "content-disposition": `attachment; filename="${filename}"`, ...SEC },
    });
  }

  if ((m = path.match(/^\/messages\/([\w-]+)\/modify$/)) && method === "POST")
    return json(await gmailJson(env, account, `/messages/${m[1]}/modify`, { method: "POST", headers: { "content-type": "application/json" }, body: await req.text() }));

  if ((m = path.match(/^\/messages\/([\w-]+)\/(trash|untrash)$/)) && method === "POST")
    return json(await gmailJson(env, account, `/messages/${m[1]}/${m[2]}`, { method: "POST" }));

  if ((m = path.match(/^\/messages\/([\w-]+)$/)) && method === "GET") {
    const mm = await gmailJson(env, account, `/messages/${m[1]}?format=full`);
    return json(q.get("raw") ? mm : parseMessage(mm));
  }

  if ((m = path.match(/^\/threads\/([\w-]+)$/)) && method === "GET") {
    const t = await gmailJson(env, account, `/threads/${m[1]}?format=full`);
    return json({ id: t.id, messages: (t.messages || []).map(parseMessage) });
  }

  if (path.startsWith("/gmail/")) {
    const init = { method, headers: { "content-type": req.headers.get("content-type") || "application/json" } };
    if (!["GET", "HEAD"].includes(method)) init.body = await req.arrayBuffer();
    const sp = new URLSearchParams(url.search);
    sp.delete("email");
    const res = await gmail(env, account, path.slice(6) + (sp.size ? `?${sp}` : ""), init);
    return new Response(res.body, { status: res.status, headers: { "content-type": res.headers.get("content-type") || "application/json", ...SEC } });
  }
  return err(404, "Not found");
}

/* ═══════════════════════════════════════════════════════════════════════════
   DESIGN — MailAPI
   World: air mail. Cold paper, airmail-blue ink, the red/blue chevron border.
   Landing = persuade (drenched blue + the envelope), docs = read, dashboard = operate.
   ═══════════════════════════════════════════════════════════════════════════ */

const CSS = String.raw`
:root{
  color-scheme:light dark;
  --paper:#f4f6fc;--surface:#fff;--sunk:#eaeefa;--ink:#0a1235;--ink2:#46507a;--line:#d9e0f2;
  --blue:#1c47d6;--blue-hi:#1538b4;--link:#1c47d6;--red:#d92d27;
  --ok:#0b7a54;--okbg:#e2f5ec;--dg:#c4231d;--dgbg:#fdecea;--dgs:#c4231d;
  --code-bg:#0c1440;--code-ink:#e6ebff;
  --font-d:"Bricolage Grotesque","Avenir Next","Segoe UI",system-ui,sans-serif;
  --font-b:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --ease:cubic-bezier(.16,1,.3,1);
}
@media(prefers-color-scheme:dark){:root{
  --paper:#080d22;--surface:#0f1633;--sunk:#151d42;--ink:#edf0fc;--ink2:#a0a9cc;--line:#222b57;
  --link:#8ea8ff;--ok:#4fd1a1;--okbg:#0e2a22;--dg:#ff8a82;--dgbg:#2e1316;--code-bg:#060a1c;
}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-behavior:smooth;scrollbar-color:var(--line) transparent}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--paper);color:var(--ink);font:15px/1.6 var(--font-b);-webkit-font-smoothing:antialiased;caret-color:var(--link);font-variant-numeric:tabular-nums}
main{flex:1}
::selection{background:var(--blue);color:#fff}
a{color:var(--link);text-underline-offset:3px}
a:hover{text-decoration-thickness:2px}
h1,h2,h3{font-family:var(--font-d);line-height:1.1;letter-spacing:-.02em;text-wrap:balance;margin:0}
:focus-visible{outline:2px solid var(--link);outline-offset:2px;border-radius:4px}
code,pre,kbd{font-family:var(--mono)}
code{font-size:.86em;background:var(--sunk);padding:.12em .4em;border-radius:5px}
pre code{background:0;padding:0;font-size:inherit}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.muted{color:var(--ink2)}
.stripe{height:6px;background:repeating-linear-gradient(135deg,#e5332d 0 10px,#fff 10px 20px,#1c47d6 20px 30px,#fff 30px 40px)}

/* top bar */
.top{position:sticky;top:0;z-index:20;background:var(--surface);border-bottom:1px solid var(--line)}
.nav{display:flex;align-items:center;justify-content:space-between;gap:16px;max-width:1120px;margin:0 auto;padding:11px 22px}
.brand{display:inline-flex;align-items:center;gap:9px;font:800 1.2rem var(--font-d);letter-spacing:-.025em;color:var(--ink);text-decoration:none}
.brand b{color:var(--link);font-weight:800}
.mark{color:var(--red);flex:none}
.nav-links{display:flex;align-items:center;gap:18px}
.nav-links a:not(.btn){color:var(--ink2);text-decoration:none;font-weight:500}
.nav-links a:not(.btn):hover,.nav-links a[aria-current]{color:var(--ink)}
.who{font-size:.85rem;color:var(--ink2);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* buttons & fields */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;padding:8px 14px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);font:600 .875rem/1.2 var(--font-b);cursor:pointer;text-decoration:none;transition:background .15s,border-color .15s,box-shadow .2s,transform .2s var(--ease)}
.btn:hover{border-color:var(--link);text-decoration:none}
.btn:active{transform:translateY(1px)}
.btn[disabled]{opacity:.5;cursor:default;pointer-events:none}
.btn-p{background:var(--blue);border-color:var(--blue);color:#fff}
.btn-p:hover{background:var(--blue-hi);border-color:var(--blue-hi)}
.btn-d{color:var(--dg)}.btn-d:hover{border-color:var(--dg)}
.btn-ds{background:var(--dgs);border-color:var(--dgs);color:#fff}.btn-ds:hover{background:#a51b16;border-color:#a51b16}
.btn-lg{padding:13px 22px;font-size:1rem;border-radius:10px}
.btn-w{background:#fff;border-color:#fff;color:#0a1235}
.btn-w:hover{border-color:#fff;box-shadow:0 10px 28px rgba(4,8,50,.4)}
.btn-gw{background:transparent;border-color:rgba(255,255,255,.55);color:#fff}
.btn-gw:hover{border-color:#fff;background:rgba(255,255,255,.12)}
input{width:100%;min-width:0;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:var(--paper);color:var(--ink);font:13px var(--mono);transition:border-color .15s}
input:hover{border-color:var(--ink2)}
input:focus-visible{outline:2px solid var(--link);outline-offset:0;border-color:var(--link)}
input::placeholder{color:var(--ink2);opacity:.8}
.lbl{display:block;font-size:.78rem;font-weight:600;color:var(--ink2);margin:0 0 6px}

/* code */
.cw{position:relative}
pre.code{margin:0;background:var(--code-bg);color:var(--code-ink);padding:14px 64px 14px 16px;border-radius:8px;overflow:auto;font-size:12.5px;line-height:1.7;tab-size:2;scrollbar-color:#3a4688 transparent}
pre.code+pre.code,.cw+.cw{margin-top:8px}
pre.code .k{color:#ffb4a8}pre.code .s{color:#9fd8ff}pre.code .m{color:#8f9bd1}
.cp{position:absolute;top:8px;right:8px;padding:3px 9px;font:600 .72rem var(--font-b);background:rgba(255,255,255,.1);color:#cdd6ff;border:1px solid rgba(255,255,255,.22);border-radius:6px;cursor:pointer}
.cp:hover{background:rgba(255,255,255,.2)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.tabs button{padding:5px 12px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink2);font:600 .8rem var(--font-b);cursor:pointer}
.tabs button:hover{color:var(--ink);border-color:var(--ink2)}
.tabs button[aria-selected=true]{background:var(--ink);border-color:var(--ink);color:var(--paper)}
[hidden]{display:none!important}

/* landing */
.hero{position:relative;background:#1a3fc4;color:#fff}
.hero::after{content:"";position:absolute;left:0;right:0;bottom:0;height:12px;background:repeating-linear-gradient(135deg,#e5332d 0 14px,#fff 14px 28px,#1c47d6 28px 42px,#fff 42px 56px)}
.hero-in{max-width:1120px;margin:0 auto;padding:76px 22px 96px;display:grid;grid-template-columns:minmax(0,1.02fr) minmax(0,.98fr);gap:56px;align-items:center}
.hero h1{font-size:clamp(2.5rem,5.2vw,4.4rem);font-weight:700;line-height:1;letter-spacing:-.035em;margin-bottom:20px}
.lead{font-size:1.1rem;color:#dbe4ff;max-width:46ch;margin:0 0 30px}
.cta{display:flex;flex-wrap:wrap;gap:12px}
.fine{margin:16px 0 0;font-size:.85rem;color:#c3d0ff}
.env{margin:0;padding:8px;border-radius:8px;background:repeating-linear-gradient(135deg,#e5332d 0 14px,#fff 14px 28px,#1c47d6 28px 42px,#fff 42px 56px);box-shadow:0 28px 60px rgba(4,8,50,.5),0 4px 14px rgba(4,8,50,.35)}
.env-in{background:#fff;color:#0a1235;border-radius:4px;padding:16px}
.env .tabs button{background:#fff;color:#46507a;border-color:#cfd7ee}
.env .tabs button[aria-selected=true]{background:#0a1235;border-color:#0a1235;color:#fff}
.env-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:12px;font-size:.78rem;color:#46507a}
.postmark{flex:none;width:60px;height:60px;color:#d92d27;transform:rotate(-12deg);font-family:var(--font-d)}
.sec{max-width:1120px;margin:0 auto;padding:92px 22px 0}
.sec h2{font-size:clamp(1.8rem,3.6vw,2.6rem);margin-bottom:10px}
.sub{color:var(--ink2);max-width:58ch;margin:0 0 30px;font-size:1.04rem}
.route{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.route li{display:grid;grid-template-columns:minmax(0,1fr) 28px minmax(0,.8fr) 28px minmax(0,1.25fr);gap:12px;align-items:center;padding:14px 16px;background:var(--surface);border:1px solid var(--line);border-radius:12px}
.route .col{font-size:.74rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--ink2);padding:0 16px;background:0;border:0}
.addr{display:inline-block;max-width:100%;font:13px var(--mono);padding:6px 10px;border:1px dashed var(--ink2);border-radius:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.box{font:600 13px var(--mono);padding:6px 10px;background:var(--ink);color:var(--paper);border-radius:6px;display:inline-block}
.arr{color:var(--red);display:block;margin:auto}
.caps{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 56px;margin:0}
.caps div{padding:22px 0;border-top:1px solid var(--line)}
.caps dt{font:700 1.15rem var(--font-d);letter-spacing:-.01em;margin-bottom:4px}
.caps dd{margin:0;color:var(--ink2);max-width:46ch}
.steps{list-style:none;margin:0;padding:0;counter-reset:s}
.steps li{counter-increment:s;display:grid;grid-template-columns:44px minmax(0,1fr);gap:0 16px;padding:22px 0;border-top:1px solid var(--line)}
.steps li::before{content:counter(s);width:34px;height:34px;border-radius:50%;background:var(--blue);color:#fff;display:grid;place-items:center;font:700 .95rem var(--font-d)}
.steps h3{font-size:1.1rem;margin:3px 0 4px}
.steps p{margin:0 0 10px;color:var(--ink2)}
.steps .cw{grid-column:2}
.close{margin-top:96px;background:#1a3fc4;color:#fff;text-align:center}
.close-in{max-width:760px;margin:0 auto;padding:72px 22px}
.close h2{font-size:clamp(2rem,4.4vw,3.2rem);margin-bottom:12px}
.close .cta{justify-content:center;margin-top:26px}
.foot{margin-top:auto;border-top:1px solid var(--line);padding:26px 22px;color:var(--ink2);font-size:.85rem}
.foot-in{max-width:1120px;margin:0 auto;display:flex;flex-wrap:wrap;gap:8px 22px;align-items:center}
.foot a{color:var(--ink2);text-decoration:none}.foot a:hover{color:var(--ink);text-decoration:underline}
.foot .sp{margin-left:auto}
.close+.foot{margin-top:0}

/* docs / prose */
.docs{max-width:1120px;margin:0 auto;padding:44px 22px 0;display:grid;grid-template-columns:200px minmax(0,1fr);gap:56px;align-items:start}
.toc{position:sticky;top:76px;display:grid;gap:2px;font-size:.9rem}
.toc a{display:block;padding:6px 10px;border-radius:6px;color:var(--ink2);text-decoration:none;font-weight:500}
.toc a:hover{background:var(--sunk);color:var(--ink)}
.doc{min-width:0;max-width:760px}
.doc>section{padding-top:8px;margin-bottom:48px;scroll-margin-top:80px}
.doc h1{font-size:clamp(2rem,4vw,2.8rem);margin-bottom:10px}
.doc h2{font-size:1.65rem;margin:0 0 12px;padding-top:28px;border-top:1px solid var(--line)}
.doc>section:first-of-type h2{border:0;padding-top:0}
.doc p{margin:0 0 14px;max-width:68ch}
.tw{overflow-x:auto;margin:14px 0;border:1px solid var(--line);border-radius:10px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{text-align:left;padding:10px 14px;vertical-align:top;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
th{background:var(--sunk);font-size:.74rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--ink2)}
td:first-child{white-space:nowrap}
td:not(:first-child) code{white-space:normal;overflow-wrap:anywhere}
.m{display:inline-block;min-width:3.9em;text-align:center;font:700 .68rem var(--mono);padding:2px 6px;border-radius:5px;margin-right:6px;vertical-align:1px}
.m.get{background:var(--sunk);color:var(--link)}
.m.post{background:var(--okbg);color:var(--ok)}
.m.delete{background:var(--dgbg);color:var(--dg)}
.m.any{background:var(--ink);color:var(--paper)}
.prose{max-width:720px;margin:0 auto;padding:56px 22px 0}
.prose h1{font-size:clamp(2rem,4vw,2.8rem);margin-bottom:6px}
.prose h2{font-size:1.25rem;margin:34px 0 8px}
.prose p{margin:0 0 12px}

/* dashboard */
.dash{max-width:1120px;margin:0 auto;padding:24px 22px 48px;display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:20px;align-items:start}
.col-main,.col-side{display:grid;gap:20px;min-width:0}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;min-width:0}
.ph{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 18px;border-bottom:1px solid var(--line)}
.ph h2{font-size:1rem;letter-spacing:-.01em}
.pb{padding:18px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.row.nw{flex-wrap:nowrap}
.hint{margin:12px 0 0;font-size:.84rem;color:var(--ink2)}
.flash{margin:20px auto 0;max-width:1120px;padding:0 22px}
.flash div{padding:10px 14px;border-radius:10px;background:var(--okbg);color:var(--ok);font-size:.9rem;font-weight:500}
.bar{display:flex;gap:8px;margin-bottom:14px}
.msgs{margin:0 -18px -18px}
.msg{position:relative;padding:12px 18px 12px 30px;border-top:1px solid var(--line)}
.msg:first-child{border-top:0}
.msg.unread::before{content:"";position:absolute;left:13px;top:19px;width:8px;height:8px;border-radius:50%;background:var(--blue)}
.msg-top{display:flex;justify-content:space-between;gap:12px;font-size:.88rem}
.msg-from{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msg-date{flex:none;color:var(--ink2);font-size:.8rem}
.msg-sub{font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msg.unread .msg-sub{font-weight:600}
.msg-snip{color:var(--ink2);font-size:.84rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.state{padding:34px 18px;text-align:center;color:var(--ink2)}
.state strong{display:block;color:var(--ink);font:700 1rem var(--font-d);margin-bottom:4px}
.state .btn{margin-top:12px}
.sk-row{padding:14px 18px;border-top:1px solid var(--line);display:grid;gap:8px}
.sk-row:first-child{border-top:0}
.sk-row i{display:block;height:11px;border-radius:6px;width:60%;background:linear-gradient(90deg,var(--sunk),var(--line),var(--sunk));background-size:200% 100%;animation:sh 1.4s linear infinite}
.sk-row i+i{width:90%}
@keyframes sh{to{background-position:-200% 0}}
.keyrow{display:flex;gap:8px;margin-bottom:10px}
.acct{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 0;border-top:1px solid var(--line);flex-wrap:wrap}
.acct:first-child{border-top:0;padding-top:0}
.acct-id{display:flex;align-items:center;gap:10px;min-width:0;font-weight:500;font-size:.9rem}
.acct-id span.e{overflow:hidden;text-overflow:ellipsis}
.av{flex:none;width:28px;height:28px;border-radius:50%;background:var(--sunk);display:grid;place-items:center;font:700 .8rem var(--font-d);text-transform:uppercase}
.tag{font-size:.7rem;font-weight:700;border-radius:999px;padding:2px 8px;background:var(--okbg);color:var(--ok)}
.btn.sm{padding:5px 10px;font-size:.8rem}
.keyout{margin-top:12px;padding:12px;border-radius:8px;background:var(--okbg);color:var(--ok);font-size:.84rem;word-break:break-all}
.keyout.bad{background:var(--dgbg);color:var(--dg)}
.keyout code{display:block;margin:6px 0 8px;background:0;padding:0;color:var(--ink);font-size:.82rem}
.akeys{margin-top:14px;display:grid}
.ak{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 0;border-top:1px solid var(--line);font-size:.84rem}
.ak code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:0;padding:0;font-size:.8rem}
.panel.danger{border-color:color-mix(in srgb,var(--dg) 35%,var(--line))}
dialog{border:1px solid var(--line);border-radius:14px;background:var(--surface);color:var(--ink);padding:22px;width:min(420px,calc(100% - 32px));box-shadow:0 24px 60px rgba(4,8,50,.35)}
dialog::backdrop{background:rgba(5,10,35,.55)}
dialog h2{font-size:1.2rem;margin-bottom:8px}
dialog p{margin:0 0 18px;color:var(--ink2)}
dialog .row{justify-content:flex-end}

@media(max-width:900px){
  .hero-in{grid-template-columns:1fr;gap:40px;padding:48px 22px 72px}
  .docs{grid-template-columns:1fr;gap:24px}
  .toc{position:static;display:flex;overflow-x:auto;gap:6px;padding-bottom:6px}
  .toc a{white-space:nowrap;border:1px solid var(--line)}
  .dash{grid-template-columns:1fr}
  .caps{grid-template-columns:1fr}
  .who{display:none}
}
@media(max-width:700px){
  .route .col{display:none}
  .route li{grid-template-columns:1fr;gap:6px}
  .arr{transform:rotate(90deg);margin:0}
  .sec{padding-top:64px}
}
@media(max-width:480px){.nav-links{gap:12px}.hide-s{display:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
`;

// Shared UI behaviour: copy buttons on code blocks + accessible tabs.
const APP_JS = String.raw`(()=>{
const $$=(s,r=document)=>[...r.querySelectorAll(s)];
$$(".cw").forEach(w=>{const pre=w.querySelector("pre");if(!pre)return;
  const b=document.createElement("button");b.type="button";b.className="cp";b.textContent="Copy";b.setAttribute("aria-label","Copy code");
  b.onclick=async()=>{try{await navigator.clipboard.writeText(pre.innerText.replace(/\n$/,""));b.textContent="Copied"}catch(e){b.textContent="Select + copy"}setTimeout(()=>b.textContent="Copy",1600)};
  w.append(b)});
$$("[data-tabs]").forEach(g=>{const tabs=$$("[role=tab]",g);
  const show=t=>tabs.forEach(x=>{const on=x===t;x.setAttribute("aria-selected",on);x.tabIndex=on?0:-1;document.getElementById(x.getAttribute("aria-controls")).hidden=!on});
  tabs.forEach((t,i)=>{t.onclick=()=>show(t);t.onkeydown=e=>{const d=e.key==="ArrowRight"?1:e.key==="ArrowLeft"?-1:0;if(!d)return;const n=tabs[(i+d+tabs.length)%tabs.length];n.focus();show(n);e.preventDefault()}});
  show(tabs[0])});
})();`;

// Dashboard controller.
const DASH_JS = String.raw`(()=>{
const $=(s,r=document)=>r.querySelector(s);
const post=(u,b)=>fetch(u,{method:"POST",headers:{"x-requested-with":"ui","content-type":"application/json"},body:b?JSON.stringify(b):undefined}).then(r=>r.json());
const el=(tag,props,...kids)=>{const e=document.createElement(tag);for(const k in (props||{})){const v=props[k];if(k==="class")e.className=v;else if(k.slice(0,2)==="on")e.addEventListener(k.slice(2),v);else e.setAttribute(k,v)}
  kids.flat().forEach(c=>{if(c!=null&&c!==false)e.append(c)});return e};
const live=m=>{$("#live").textContent=m};
const decodeHtml=s=>{const t=document.createElement("textarea");t.innerHTML=s||"";return t.value};
const copy=async(text,btn,label)=>{label=label||btn.textContent;try{await navigator.clipboard.writeText(text);btn.textContent="Copied"}catch(e){btn.textContent="Press Ctrl+C"}setTimeout(()=>btn.textContent=label,1600)};
const skeleton=n=>{const f=document.createDocumentFragment();for(let i=0;i<n;i++)f.append(el("div",{class:"sk-row"},el("i"),el("i")));return f};

/* confirm dialog (native <dialog>) */
const dlg=$("#dlg");
const confirmDlg=o=>new Promise(res=>{
  $("#dlg-t").textContent=o.title;$("#dlg-b").textContent=o.body;
  const ok=$("#dlg-ok");ok.textContent=o.ok;ok.className="btn "+(o.danger?"btn-ds":"btn-p");
  dlg.returnValue="";dlg.addEventListener("close",()=>res(dlg.returnValue==="ok"),{once:true});dlg.showModal()});

/* API key */
const keyEl=$("#key");
$("#show").onclick=()=>{const hide=keyEl.type==="password";keyEl.type=hide?"text":"password";$("#show").textContent=hide?"Hide":"Show"};
$("#copy").onclick=e=>copy(keyEl.value,e.target,"Copy key");
$("#copybase").onclick=e=>copy($("#base").value,e.target,"Copy");
$("#rotate").onclick=async()=>{
  if(!await confirmDlg({title:"Regenerate your key?",body:"Your current key stops working immediately. Anything using it will need the new one.",ok:"Regenerate"}))return;
  const r=await post("/app/rotate");if(r.api_key){keyEl.value=r.api_key;live("New API key generated")}};

/* session */
$("#logout").onclick=()=>post("/app/logout").then(()=>{location="/"});
$("#addacc").onclick=()=>{location="/auth/login?link=1"};
const mailIn=$("#mail-in");

/* accounts: every linked account is live at once; "Open inbox" only chooses which one to look at */
function renderAccounts(accs){
  const box=$("#accounts");box.textContent="";
  if(!accs.length){box.textContent="No accounts.";return}
  accs.forEach(a=>{
    const id=el("div",{class:"acct-id"},el("span",{class:"av","aria-hidden":"true"},a.email[0]),el("span",{class:"e"},a.email));
    const btns=el("div",{class:"row nw"},
      el("button",{class:"btn sm",onclick:()=>{mailIn.value=a.email;loadInbox(a.email)}},"Open inbox"),
      el("button",{class:"btn sm btn-d",onclick:async()=>{
        if(!await confirmDlg({title:"Remove "+a.email+"?",body:"Google access is revoked and its key and stored data are deleted.",ok:"Remove",danger:true}))return;
        post("/app/unlink",{email:a.email}).then(r=>{location=r.next?"/dashboard":"/"})}},"Remove"));
    box.append(el("div",{class:"acct"},id,btns))})}
$("#addacc").disabled=false;

/* inbox */
let ctl;
const fromName=f=>{f=f||"";const m=f.match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>/);return (m&&m[1].trim())||(m&&m[2])||f||"(unknown sender)"};
const fmtDate=s=>{const d=new Date(s);if(isNaN(d))return"";return d.toDateString()===new Date().toDateString()?d.toLocaleTimeString([],{hour:"numeric",minute:"2-digit"}):d.toLocaleDateString([],{month:"short",day:"numeric"})};
function loadInbox(email){
  if(ctl)ctl.abort();ctl=new AbortController();
  const box=$("#inbox");box.setAttribute("aria-busy","true");box.textContent="";box.append(skeleton(5));
  $("#mail-clear").hidden=!email;
  const retry=()=>el("button",{class:"btn",onclick:()=>loadInbox(email)},"Try again");
  fetch("/app/inbox"+(email?"?email="+encodeURIComponent(email):""),{signal:ctl.signal}).then(r=>r.json()).then(d=>{
    box.textContent="";box.setAttribute("aria-busy","false");
    if(d.error){box.append(el("div",{class:"state"},el("strong",null,"Couldn't load mail"),d.error,el("br"),retry()));return}
    $("#mb").textContent=d.mailbox||"";
    const filtered=!!d.mailbox&&!!d.account&&d.mailbox!==d.account;
    if(!d.messages.length){box.append(el("div",{class:"state"},el("strong",null,filtered?"Nothing sent to "+d.mailbox+" yet":"This inbox is empty"),filtered?"Mail addressed to this address will show up here.":"New mail will show up here."));live("No messages");return}
    d.messages.forEach(m=>box.append(el("article",{class:"msg"+((m.labels||[]).indexOf("UNREAD")>-1?" unread":"")},
      el("div",{class:"msg-top"},el("span",{class:"msg-from"},fromName(m.from)),el("time",{class:"msg-date"},fmtDate(m.date))),
      el("div",{class:"msg-sub"},decodeHtml(m.subject)||"(no subject)"),
      el("div",{class:"msg-snip"},(filtered&&m.to?"to "+m.to+" — ":"")+decodeHtml(m.snippet)))));
    live(d.messages.length+" messages loaded")
  }).catch(e=>{if(e.name==="AbortError")return;box.textContent="";box.setAttribute("aria-busy","false");box.append(el("div",{class:"state"},el("strong",null,"Couldn't load mail"),"Check your connection.",el("br"),retry()))})}
$("#mail-apply").onclick=()=>loadInbox(mailIn.value.trim()||null);
$("#mail-clear").onclick=()=>{mailIn.value="";loadInbox(null)};
mailIn.addEventListener("keydown",e=>{if(e.key==="Enter")$("#mail-apply").click()});

fetch("/app/state").then(r=>r.json()).then(s=>renderAccounts(s.accounts||[])).catch(()=>renderAccounts([]));
loadInbox(null);
})();`;

// Content-hashed version string: assets are cached "immutable" and bust automatically on any change.
const hash = (s) => {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
};
const BUILD = hash(CSS + APP_JS + DASH_JS);
const ASSETS = { "app.css": ["text/css", CSS], "app.js": ["text/javascript", APP_JS], "dash.js": ["text/javascript", DASH_JS] };

/* ─────────────────────────────── shared markup ─────────────────────────────── */

const FONT_URL = "https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500..800&amp;display=swap";
const FAVICON =
  "data:image/svg+xml," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#1c47d6"/><rect x="6" y="9" width="20" height="14" rx="2.5" fill="none" stroke="#fff" stroke-width="2"/><path d="M7 11l9 7 9-7" fill="none" stroke="#fff" stroke-width="2" stroke-linejoin="round"/></svg>'
  );
const MARK = `<svg class=mark width=26 height=26 viewBox="0 0 26 26" aria-hidden=true><rect x=1.5 y=4.5 width=23 height=17 rx=3 fill=none stroke=currentColor stroke-width=2 /><path d="M3 7.5l10 8 10-8" fill=none stroke=currentColor stroke-width=2 stroke-linejoin=round /></svg>`;
const GLOGO = `<svg width=18 height=18 viewBox="0 0 48 48" aria-hidden=true><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9.1 3.6l6.8-6.8C35.9 2.4 30.4 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.6 17.7 9.5 24 9.5z"/><path fill="#4285F4" d="M46.1 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.4c-.5 2.9-2.2 5.3-4.6 6.9l7.4 5.7c4.3-4 6.9-9.9 6.9-17.1z"/><path fill="#FBBC05" d="M10.5 28.7c-.5-1.4-.8-3-.8-4.7s.3-3.2.8-4.7l-7.9-6.1C.9 16.4 0 20.1 0 24s.9 7.6 2.6 10.8l7.9-6.1z"/><path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.4-5.7c-2.1 1.4-4.8 2.3-8.5 2.3-6.3 0-11.600-4.1-13.5-9.8l-7.900 6.100C6.5 42.6 14.6 48 24 48z"/></svg>`;
const ARROW = `<svg class=arr width=24 height=14 viewBox="0 0 24 14" aria-hidden=true><path d="M1 7h20M16 2l5 5-5 5" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round /></svg>`;

function doc({ title, desc = "", body, scripts = ["app"], head = "" }) {
  return `<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${esc(title)}</title><meta name=description content="${esc(desc)}"><meta name=theme-color content="#1a3fc4"><link rel=icon href="${FAVICON}"><link rel=preconnect href=https://fonts.googleapis.com><link rel=preconnect href=https://fonts.gstatic.com crossorigin><link rel=stylesheet href="/a/app.css?v=${BUILD}"><link rel=preload as=style href="${FONT_URL}" onload="this.onload=null;this.rel='stylesheet'"><noscript><link rel=stylesheet href="${FONT_URL}"></noscript>${head}</head><body>${body}${scripts.map((s) => `<script src="/a/${s}.js?v=${BUILD}" defer></script>`).join("")}</body></html>`;
}

// Static pages are identical for everyone (no per-user work, no KV reads) so they can be cached hard.
const navPublic = (current) =>
  `<header class=top><div class=stripe></div><nav class=nav aria-label=Main><a class=brand href=/ aria-label="MailAPI home">${MARK}<span>Mail<b>API</b></span></a><div class=nav-links><a href=/docs${current === "docs" ? " aria-current=page" : ""}>Docs</a><a id=navcta class="btn btn-p" href=/auth/login>Sign in</a></div></nav></header><script>if(/mailapi=1/.test(document.cookie)){var c=document.getElementById("navcta");c.href="/dashboard";c.textContent="Dashboard"}</script>`;
const navApp = (email) =>
  `<header class=top><div class=stripe></div><nav class=nav aria-label=Main><a class=brand href=/dashboard aria-label="MailAPI dashboard">${MARK}<span>Mail<b>API</b></span></a><div class=nav-links><a href=/docs>Docs</a><span class=who title="Signed in as">${esc(email)}</span><button id=logout class=btn type=button>Sign out</button></div></nav></header>`;
const footer = `<footer class=foot><div class=foot-in><a href=/>MailAPI</a><a href=/docs>Docs</a><a href=/privacy>Privacy</a><a href=/terms>Terms</a><a href=https://github.com/nullstacks/mailapi rel="noopener">GitHub</a><span class=sp>Gmail API · Cloudflare Workers</span></div></footer>`;

const STATIC_HEADERS = { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300, stale-while-revalidate=86400", ...SEC };
const staticPage = (html) => new Response(html, { headers: STATIC_HEADERS });
const privatePage = (html, extra = {}) =>
  new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "private, no-store", ...SEC, ...extra } });

const memo = new Map();
const memoize = (key, fn) => {
  let v = memo.get(key);
  if (v === undefined) memo.set(key, (v = fn()));
  return v;
};

// JSON syntax tint for the sample responses.
const hl = (s) => esc(s).replace(/(&#34;(?:(?!&#34;).)*?&#34;)(\s*:)?/g, (_, str, colon) => (colon ? `<span class=k>${str}</span>${colon}` : `<span class=s>${str}</span>`));
const code = (src, { html = false } = {}) => `<div class=cw><pre class=code><code>${html ? src : esc(src)}</code></pre></div>`;

function errPage(title, msg) {
  return privatePage(
    doc({ title: `${title} — MailAPI`, body: `${navPublic()}<main class=prose><h1>${esc(title)}</h1><p class=muted>${esc(msg)}</p><p><a class="btn btn-p" href=/>Back to MailAPI</a></p></main>${footer}` })
  );
}

/* ─────────────────────────────────── pages ─────────────────────────────────── */

function homePage(origin) {
  const readCurl = `curl -H "Authorization: Bearer $KEY" \\\n  "${origin}/v1/messages?q=is:unread&maxResults=2"`;
  const readOut = `{\n  "mailbox": "you@gmail.com",\n  "messages": [\n    {\n      "from": "GitHub <noreply@github.com>",\n      "subject": "Your build passed",\n      "labels": ["INBOX", "UNREAD"]\n    }\n  ]\n}`;
  const aliasCurl = `curl -H "Authorization: Bearer $KEY" \\\n  "${origin}/v1/messages?email=you%2Bnetflix%40gmail.com"`;
  const aliasOut = `{\n  "mailbox": "you+netflix@gmail.com",\n  "messages": [\n    {\n      "from": "Netflix <info@netflix.com>",\n      "subject": "Your verification code",\n      "to": "you+netflix@gmail.com"\n    }\n  ]\n}`;
  const sendCurl = `curl -X POST "${origin}/v1/messages/send" \\\n  -H "Authorization: Bearer $KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"to":"friend@example.com","subject":"Hi","text":"sent via my API"}'`;
  const sendOut = `{\n  "id": "18f3a9c2b7e1d604",\n  "threadId": "18f3a9c2b7e1d604",\n  "labelIds": ["SENT"]\n}`;
  const panel = (n, curl, out, hidden) =>
    `<div role=tabpanel id=p${n} aria-labelledby=b${n}${hidden ? " hidden" : ""}>${code(curl)}${code(hl(out), { html: true }).replace("<pre class=code>", "<pre class=code aria-label='Sample response'>")}</div>`;
  const postmark = `<svg class=postmark viewBox="0 0 64 64" aria-hidden=true><circle cx=32 cy=32 r=29 fill=none stroke=currentColor stroke-width=2 /><circle cx=32 cy=32 r=23 fill=none stroke=currentColor stroke-width=1 stroke-dasharray="2 3" /><text x=32 y=33 text-anchor=middle font-size=15 font-weight=800 fill=currentColor>200</text><text x=32 y=45 text-anchor=middle font-size=9 font-weight=700 letter-spacing=1.5 fill=currentColor>OK</text></svg>`;
  const route = (a, b, c) => `<li><span class=addr>${esc(a)}</span>${ARROW}<span class=box>${esc(b)}</span>${ARROW}<span class=addr>${esc(c)}</span></li>`;

  return doc({
    title: "MailAPI — Your Gmail, as a REST API",
    desc: "Sign in with Google and get a personal API key to read, search and send your own Gmail from any script. Disposable aliases built in.",
    head: `<script>if(/mailapi=1/.test(document.cookie))location.replace("/dashboard")</script>`,
    body: `${navPublic()}<main>
<section class=hero><div class=hero-in>
  <div>
    <h1>Your Gmail,<br>as a REST&nbsp;API.</h1>
    <p class=lead>Sign in with Google and get a personal key to read, search and send your own mail from any script. Disposable aliases are built in: one inbox, unlimited addresses, one endpoint that works out the rest.</p>
    <div class=cta><a class="btn btn-w btn-lg" href=/auth/login>${GLOGO} Sign in with Google</a><a class="btn btn-gw btn-lg" href=/docs>Read the docs</a></div>
    <p class=fine>Works with any Gmail address · tokens encrypted at rest · revoke anytime · <a href=https://github.com/nullstacks/mailapi rel=noopener style="color:inherit">open source</a></p>
  </div>
  <figure class=env><div class=env-in data-tabs>
    <div class=tabs role=tablist aria-label="Example requests">
      <button role=tab id=b1 aria-controls=p1 aria-selected=true type=button>Read inbox</button>
      <button role=tab id=b2 aria-controls=p2 type=button>Temp alias</button>
      <button role=tab id=b3 aria-controls=p3 type=button>Send</button>
    </div>
    ${panel(1, readCurl, readOut)}${panel(2, aliasCurl, aliasOut, true)}${panel(3, sendCurl, sendOut, true)}
    <div class=env-foot><span>Sample responses. Plain curl, no SDK.</span>${postmark}</div>
  </div></figure>
</div></section>

<section class=sec>
  <h2>One inbox, unlimited addresses.</h2>
  <p class=sub>Gmail ignores dots and anything after the <code>+</code>. Hand every site its own address, then ask the API for just that address.</p>
  <ul class=route aria-label="How aliases route">
    <li class=col aria-hidden=true><span>Address you give a site</span><span></span><span>Lands in</span><span></span><span>Query it with</span></li>
    ${route("you+netflix@gmail.com", "you@gmail.com", "?email=you+netflix@gmail.com")}
    ${route("y.o.u+shop@gmail.com", "you@gmail.com", "?email=y.o.u+shop@gmail.com")}
    ${route("you+ci@gmail.com", "you@gmail.com", "?email=you+ci@gmail.com")}
  </ul>
</section>

<section class=sec>
  <h2>Built for scripts and automations.</h2>
  <p class=sub>Everything a mailbox integration needs, nothing it doesn't.</p>
  <dl class=caps>
    <div><dt>One key, your whole mailbox</dt><dd>A personal API key to list, read and send mail. Rotate or delete it whenever you want.</dd></div>
    <div><dt>Multiple Google accounts</dt><dd>Link several Gmail accounts to one key and use them all at the same time. Each request just names the address it wants.</dd></div>
    <div><dt>Disposable aliases</dt><dd>+tag and dot aliases are free temp addresses. Pass one as <code>email</code> and only its mail comes back.</dd></div>
    <div><dt>Auto-detected addresses</dt><dd>One <code>email</code> parameter for everything: a plain address returns its inbox, an alias returns just that alias. No separate endpoint.</dd></div>
    <div><dt>Fast and serverless</dt><dd>Runs on Cloudflare Workers at the edge. No servers to manage, nothing to maintain.</dd></div>
    <div><dt>Open source</dt><dd>The whole project is open source. Read the code, self-host it on your own Cloudflare account, or send a pull request on <a href=https://github.com/nullstacks/mailapi rel=noopener>GitHub</a>.</dd></div>
    <div><dt>Zero lock-in</dt><dd>Delete your account in one click. Google access is revoked and all stored data wiped instantly.</dd></div>
  </dl>
</section>

<section class=sec>
  <h2>Up and running in two minutes.</h2>
  <p class=sub>Everything works from plain curl.</p>
  <ol class=steps>
    <li><div><h3>Sign in with Google</h3><p>Approve read and send access. You land on a dashboard with your API key.</p></div></li>
    <li><div><h3>Read your inbox</h3><p>Any Gmail search works as the <code>q</code> parameter.</p></div>${code(`curl -H "Authorization: Bearer $KEY" "${origin}/v1/messages?q=is:unread"`)}</li>
    <li><div><h3>Make a temp address</h3><p>Give a site <code>you+netflix@gmail.com</code>, then read only that alias.</p></div>${code(`curl -H "Authorization: Bearer $KEY" "${origin}/v1/messages?email=you%2Bnetflix%40gmail.com"`)}</li>
    <li><div><h3>Send mail</h3><p>One POST. Add <code>from</code> to send as any linked address or alias.</p></div>${code(`{"to":"friend@example.com","subject":"Hi","text":"sent via my API"}`)}</li>
  </ol>
</section>

<section class=close style="margin-top:96px"><div class=stripe></div><div class=close-in>
  <h2>Get your key in two minutes.</h2>
  <p class=lead style="margin:0 auto">No servers, no SDK. Just your mailbox and curl.</p>
  <div class=cta><a class="btn btn-w btn-lg" href=/auth/login>${GLOGO} Sign in with Google</a></div>
</div></section>
</main>${footer}`,
  });
}

const ep = (m, p) => `<span class="m ${m.toLowerCase()}">${m}</span><code>${esc(p)}</code>`;
const table = (head, rows) =>
  `<div class=tw><table><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;

function docsPage(origin) {
  const c = (s) => `<code>${esc(s)}</code>`;
  return doc({
    title: "Docs — MailAPI",
    desc: "MailAPI REST reference: authentication, accounts, addresses and messages.",
    body: `${navPublic("docs")}<div class=docs>
<nav class=toc aria-label="On this page"><a href=#auth>Authentication</a><a href=#accounts>Accounts</a><a href=#aliases>Addresses &amp; temp mail</a><a href=#messages>Messages</a><a href=#errors>Errors</a></nav>
<article class=doc>
<section id=auth>
  <h1>MailAPI reference</h1>
  <p class=muted>Base URL ${c(origin)}. All responses are JSON. MailAPI is open source: <a href=https://github.com/nullstacks/mailapi rel=noopener>github.com/nullstacks/mailapi</a>.</p>
  <h2>Authentication</h2>
  <p>Send your key as ${c("Authorization: Bearer YOUR_KEY")} (or the ${c("X-API-Key")} header). Sign in at <a href=/auth/login>/auth/login</a>; the dashboard shows your ${c("gmk_…")} key. One key works for every linked account.</p>
</section>

<section id=accounts>
  <h2>Accounts</h2>
  <p>Link more Gmail accounts on the dashboard. One key reaches every linked mailbox and they are all live at the same time: pick the mailbox per request with ${c("email")}. If you leave it out, the key's own account is used.</p>
  ${table(["Endpoint", "Description"], [
    [ep("GET", "/v1/me"), "Key owner and linked accounts"],
    [ep("GET", "/v1/accounts"), "All linked accounts and the default"],
    [ep("POST", "/v1/key/rotate"), "Rotate your key (the old one dies)"],
    [ep("DELETE", "/v1/account?email=…"), "Revoke Google access and delete that account's data"],
  ])}
</section>

<section id=aliases>
  <h2>Addresses &amp; temp mail</h2>
  <p>Gmail ignores dots and anything after ${c("+")}: ${c("p.i.us+news@gmail.com")} is the same inbox as ${c("pius@gmail.com")}. Free disposable email: one inbox, unlimited addresses. Pass any address as ${c("email")} and it is detected for you: a linked address returns that whole inbox, a +tag or dot variant returns only mail addressed to it. There is no separate alias endpoint or key.</p>
  ${table(["Request", "Result"], [
    [ep("GET", "/v1/messages?email=you@gmail.com"), "The whole inbox of that linked account"],
    [ep("GET", "/v1/messages?email=you+netflix@gmail.com"), "Only mail addressed to that alias"],
    [ep("POST", "/v1/messages/send"), `Send from any linked address or alias: ${c('"from":"you+shop@gmail.com"')}`],
  ])}
  ${code(`# two accounts and a temp alias, same key, all at once
curl -H "Authorization: Bearer $KEY" "${origin}/v1/messages?email=a%40gmail.com" &
curl -H "Authorization: Bearer $KEY" "${origin}/v1/messages?email=b%40gmail.com" &
curl -H "Authorization: Bearer $KEY" "${origin}/v1/messages?email=a%2Bnetflix%40gmail.com&maxResults=5" &
wait`)}
</section>

<section id=messages>
  <h2>Messages</h2>
  <p>Every route below also takes ${c("?email=")} to choose the mailbox (message and thread ids belong to one account, so pass the same address you listed with).</p>
  ${table(["Endpoint", "Description"], [
    [ep("GET", "/v1/messages"), `List. Params: ${c("email")}, ${c("q")} (Gmail search), ${c("maxResults")} (≤50), ${c("pageToken")}, ${c("labelIds")}, ${c("ids_only=1")}`],
    [ep("GET", "/v1/messages/:id"), `Parsed message: text, html, headers, attachments. ${c("?raw=1")} for the full Gmail payload`],
    [ep("GET", "/v1/messages/:id/attachments/:attId"), `Binary download (${c("filename=")}, ${c("type=")} optional)`],
    [ep("POST", "/v1/messages/send"), c("{to, cc?, bcc?, subject, text?, html?, attachments?:[{filename, contentType, content}], from?, threadId?}")],
    [ep("POST", "/v1/messages/:id/modify"), c('{"addLabelIds":[],"removeLabelIds":[]}')],
    [ep("POST", "/v1/messages/:id/trash"), `Move to trash. ${c("/untrash")} moves it back`],
    [ep("GET", "/v1/threads/:id"), "Whole thread, parsed"],
    [ep("GET", "/v1/labels"), "All labels"],
    [ep("ANY", "/v1/gmail/*"), `Raw passthrough to the Gmail REST API (${c("/v1/gmail/drafts")}, ${c("/v1/gmail/history")} …)`],
  ])}
  ${code(`curl -H "Authorization: Bearer $KEY" \\
  "${origin}/v1/messages?q=is:unread&maxResults=5"

curl -X POST "${origin}/v1/messages/send" \\
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \\
  -d '{"to":"friend@example.com","subject":"Hi","text":"sent via my API"}'`)}
</section>

<section id=errors>
  <h2>Errors</h2>
  ${table(["Status", "Meaning"], [
    [c("401"), "Bad or missing key, or the Google grant expired (the message says “Re-authorize”: sign in again)"],
    [c("404"), "Unknown route or id, or an email that isn't a linked account or an alias of one"],
    [c("429"), "Upstream Gmail quota"],
  ])}
</section>
</article></div>${footer}`,
  });
}

const prosePage = (title, inner) =>
  doc({ title: `${title} — MailAPI`, body: `${navPublic()}<main class=prose><h1>${title}</h1><p class=muted>Last updated: October 7, 2026</p>${inner}</main>${footer}` });

function privacyPage() {
  return prosePage(
    "Privacy Policy",
    `<p>This service ("MailAPI") lets you connect your own Gmail mailbox and use it through a personal API key. This policy describes how your Google user data is accessed, used, stored, and shared.</p>
<h2>What we access</h2>
<p>When you sign in, you grant MailAPI the Gmail scope <code>https://www.googleapis.com/auth/gmail.modify</code> plus basic profile scopes (<code>openid</code>, <code>email</code>). This allows the service to read your messages, send messages on your behalf, and manage labels in your mailbox, only when you (or someone holding your personal API key) request it.</p>
<h2>How your data is used</h2>
<p>Google user data obtained through the Gmail API is used solely to provide the user-facing features you request: listing, reading, sending, and organizing your own mail through the dashboard and the API. MailAPI complies with the <a href="https://developers.google.com/terms/api-services-user-data-policy">Google API Services User Data Policy</a>, including its Limited Use requirements.</p>
<p>MailAPI does <b>not</b>: sell your data, transfer it to third parties, use it for advertising or retargeting, use it to train AI or machine-learning models, or allow humans to read your mail, except where necessary for security investigations, to comply with law, or with your explicit consent.</p>
<h2>What we store</h2>
<p>In Cloudflare Workers KV storage we keep: your Google account ID, your email address, an encrypted copy of your OAuth refresh token (AES-256-GCM), a short-lived cached access token, and a SHA-256 hash of your API key (the key itself is stored encrypted so the dashboard can show it). Message contents are not stored; they are fetched from Google on request and returned to you directly.</p>
<h2>Data retention and deletion</h2>
<p>Nothing is kept after you delete your account. "Delete account" on the dashboard immediately revokes your Google OAuth grant at Google and deletes your stored record, keys, and tokens from our storage. You can also revoke access anytime at <a href="https://myaccount.google.com/permissions">myaccount.google.com/permissions</a>.</p>
<h2>Security</h2>
<p>The service runs on Cloudflare Workers. Google tokens are encrypted at rest, API keys are stored only as hashes, dashboard sessions use HttpOnly Secure cookies, and all traffic is served over HTTPS.</p>
<h2>Contact</h2>
<p>Questions about this policy or your data: <a href="mailto:pushkarsingh4343@gmail.com">pushkarsingh4343@gmail.com</a>.</p>`
  );
}

function termsPage() {
  return prosePage(
    "Terms of Service",
    `<p>By connecting your Gmail account to MailAPI ("the service") you agree to these terms.</p>
<h2>The service</h2>
<p>MailAPI provides a personal API key and dashboard for accessing your own Gmail mailbox through the Gmail API. The service acts only on requests authorized by your key.</p>
<h2>Your responsibility</h2>
<p>Your API key grants full access to your mailbox as configured. Keep it secret; you are responsible for all activity performed with it. Rotate it from the dashboard if it is ever exposed.</p>
<h2>Availability and liability</h2>
<p>The service is provided "as is" without warranties of any kind. It depends on Google's Gmail API and Cloudflare's platform; availability may vary. To the maximum extent permitted by law, the operator is not liable for damages arising from use of the service, lost messages, or downtime.</p>
<h2>Termination</h2>
<p>You may stop using the service at any time by deleting your account from the dashboard, which revokes Google access and erases all stored data. The operator may suspend accounts used for abuse, spam, or unlawful activity.</p>
<h2>Contact</h2>
<p>Questions: <a href="mailto:pushkarsingh4343@gmail.com">pushkarsingh4343@gmail.com</a>. See also our <a href="/privacy">Privacy Policy</a>.</p>`
  );
}

function dashboardPage(user, origin, key, flash) {
  const flashHtml = flash?.linked
    ? `<div class=flash role=status><div>Linked ${esc(flash.linked)}. It now shares this dashboard and key.</div></div>`
    : flash?.relinked
      ? `<div class=flash role=status><div>Address updated. Your key was rotated because your Google address changed.</div></div>`
      : "";
  const sk = `<div class=sk-row><i></i><i></i></div>`.repeat(5);
  const O = esc(origin);
  const qs = (n, label, src, hidden) =>
    `<div role=tabpanel id=q${n} aria-labelledby=qb${n}${hidden ? " hidden" : ""}>${code(src)}</div>`;
  return doc({
    title: "Dashboard — MailAPI",
    scripts: ["app", "dash"],
    body: `${navApp(user.email)}${flashHtml}
<main class=dash>
<div class=col-main>
  <section class=panel aria-labelledby=h-inbox>
    <div class=ph><h2 id=h-inbox>Inbox</h2><span class="muted hide-s" style="font-size:.84rem" id=mb></span></div>
    <div class=pb>
      <div class=bar><input id=mail-in placeholder="Any linked address or alias, e.g. you+netflix@gmail.com" aria-label="Mailbox" autocomplete=off spellcheck=false inputmode=email><button id=mail-apply class="btn btn-p" type=button>Open</button><button id=mail-clear class=btn type=button hidden>Default</button></div>
      <div id=inbox class=msgs aria-live=polite aria-busy=true>${sk}</div>
    </div>
  </section>
  <section class=panel aria-labelledby=h-qs>
    <div class=ph><h2 id=h-qs>Quick start</h2><a href=/docs style="font-size:.85rem">Full reference</a></div>
    <div class=pb data-tabs>
      <div class=tabs role=tablist aria-label="Examples">
        <button role=tab id=qb1 aria-controls=q1 aria-selected=true type=button>Unread</button>
        <button role=tab id=qb2 aria-controls=q2 type=button>Other address</button>
        <button role=tab id=qb3 aria-controls=q3 type=button>Send</button>
      </div>
      ${qs(1, "", `curl -H "Authorization: Bearer YOUR_KEY" \\\n  "${origin}/v1/messages?q=is:unread&maxResults=5"`)}
      ${qs(2, "", `curl -H "Authorization: Bearer YOUR_KEY" \\\n  "${origin}/v1/messages?email=you%2Btag%40gmail.com"`, true)}
      ${qs(3, "", `curl -X POST ${origin}/v1/messages/send \\\n  -H "Authorization: Bearer YOUR_KEY" -H "Content-Type: application/json" \\\n  -d '{"from":"you+tag@gmail.com","to":"friend@example.com","subject":"Hi","text":"hello"}'`, true)}
    </div>
  </section>
</div>

<div class=col-side>
  <section class=panel aria-labelledby=h-key>
    <div class=ph><h2 id=h-key>API key</h2></div>
    <div class=pb>
      <label class=lbl for=key>Personal key</label>
      <div class=keyrow><input id=key type=password readonly value="${esc(key)}" autocomplete=off spellcheck=false><button id=show class=btn type=button>Show</button></div>
      <div class=row><button id=copy class="btn btn-p" type=button>Copy key</button><button id=rotate class=btn type=button>Regenerate</button></div>
      <p class=hint>Works on every linked account at once. Choose one per request with <code>email</code>. Keep it secret.</p>
      <label class=lbl for=base style="margin-top:16px">Base URL</label>
      <div class=keyrow style="margin:0"><input id=base readonly value="${O}"><button id=copybase class=btn type=button>Copy</button></div>
    </div>
  </section>

  <section class=panel aria-labelledby=h-acc>
    <div class=ph><h2 id=h-acc>Accounts</h2></div>
    <div class=pb>
      <div id=accounts class=muted>Loading…</div>
      <div style="margin-top:14px"><button id=addacc class=btn type=button>${GLOGO} Link another account</button></div>
      <p class=hint>All linked accounts share this key and stay live together. “Open inbox” only changes which one you view here.</p>
    </div>
  </section>

</div>
</main>
<div id=live class=sr aria-live=polite></div>
<dialog id=dlg aria-labelledby=dlg-t><form method=dialog><h2 id=dlg-t></h2><p id=dlg-b></p><div class=row><button class=btn value=cancel>Cancel</button><button id=dlg-ok class="btn btn-p" value=ok></button></div></form></dialog>
${footer}`,
  });
}

/* ─────────────────────────────── dashboard routes ─────────────────────────────── */

async function appRoutes(req, env, url) {
  const user = await session(req, env);
  if (!user) return err(401, "Not signed in");
  if (req.method === "POST" && !req.headers.get("x-requested-with")) return err(403, "Forbidden");
  const readBody = async () => {
    try { return await req.json(); } catch { return {}; }
  };

  switch (url.pathname) {
    case "/app/state": {
      const accounts = (await linkedUsers(env, user)).map((u) => ({ email: u.email }));
      return json({ accounts });
    }
    case "/app/unlink": {
      const email = String((await readBody()).email || "").toLowerCase();
      const found = (await linkedUsers(env, user)).find((u) => u.email.toLowerCase() === email);
      if (!found) return err(404, "That account is not linked");
      const rest = await deleteAccount(env, found);
      if (found.sub !== user.sub) return json({ ok: true, next: true });
      const sid = getSid(req);
      if (rest.length && sid) {
        await env.KV.put(`sess:${await sha256(sid)}`, rest[0], { expirationTtl: SESSION_TTL });
        return json({ ok: true, next: true });
      }
      return logout(req, env);
    }
    case "/app/inbox": {
      const email = url.searchParams.get("email");
      return api(req, env, new URL("/v1/messages?maxResults=10" + (email ? "&email=" + encodeURIComponent(email) : ""), url), { user });
    }
    case "/app/rotate":
      return json({ api_key: await issueApiKey(env, user) });
    case "/app/logout":
      return logout(req, env);
  }
  return err(404, "Not found");
}

async function logout(req, env) {
  const sid = getSid(req);
  if (sid) await env.KV.delete(`sess:${await sha256(sid)}`);
  const h = clearedHeaders();
  h.set("content-type", "application/json");
  return new Response(JSON.stringify({ ok: true }), { headers: h });
}

/* ───────────────────────────────── router ───────────────────────────────── */

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const { pathname } = url;
    try {
      // Static, user-independent pages: no KV, built once per isolate, cacheable.
      if (pathname === "/") return staticPage(memoize(`home|${url.origin}`, () => homePage(url.origin)));
      if (pathname === "/docs") return staticPage(memoize(`docs|${url.origin}`, () => docsPage(url.origin)));
      if (pathname === "/privacy") return staticPage(memoize("privacy", privacyPage));
      if (pathname === "/terms") return staticPage(memoize("terms", termsPage));

      if (pathname.startsWith("/a/")) {
        const a = ASSETS[pathname.slice(3)];
        if (!a) return err(404, "Not found");
        return new Response(a[1], { headers: { "content-type": `${a[0]}; charset=utf-8`, "cache-control": "public, max-age=31536000, immutable", ...SEC } });
      }

      if (pathname === "/dashboard") {
        const user = await session(req, env);
        if (!user) return new Response(null, { status: 302, headers: (() => { const h = clearedHeaders(); h.set("location", "/"); return h; })() });
        const flash = url.searchParams.get("linked") ? { linked: url.searchParams.get("linked") } : url.searchParams.get("relinked") ? { relinked: true } : null;
        return privatePage(dashboardPage(user, url.origin, await readApiKey(env, user), flash));
      }
      if (pathname === "/auth/login") return login(req, url, env);
      if (pathname === "/auth/callback") return callback(req, url, env);
      if (pathname.startsWith("/app/")) return await appRoutes(req, env, url);

      if (pathname.startsWith("/v1/")) {
        const principal = await resolveKeyPrincipal(req, env);
        if (!principal || !principal.user) return err(401, "Invalid or missing API key");
        return await api(req, env, url, principal);
      }
      return err(404, "Not found");
    } catch (e) {
      if (e.reauth) return err(401, `Google access expired or revoked. Re-authorize at ${url.origin}/auth/login`);
      return err(e.status || 500, e.message || "Internal error");
    }
  },
};
