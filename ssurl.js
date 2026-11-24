// ============================================================
// Cloudflare Worker Short URL v2.6.0
//
// Existing KV namespace and keys are preserved:
//   shortCode -> target URL
//   SHA256(target URL) -> shortCode
//   SYS_CE / SYS_SK / SYS_SS
//
// Required:
//   KV binding: LINKS (existing namespace)
//   Secret: ADMIN_PASS
//
// Optional:
//   Secret: TURNSTILE_SECRET
//     Fallback: legacy LINKS/SYS_SS
//   Secret: CF_PURGE_TOKEN
//   Variable: CF_ZONE_ID
//   Rate Limit bindings:
//     CREATE_LIMITER
//     ADMIN_LOGIN_LIMITER
//
// Cache:
//   Cloudflare Cache API
//   Maximum cache lifetime: 86400 seconds
//   Limited links never cache beyond their expiry.
//   Legacy records use KV list() to inspect their original expiry.
// ============================================================

const VERSION = "2.6.0";

const CACHE_TTL_SECONDS = 86400;
const KV_CACHE_TTL_SECONDS = 30;

const MAX_BODY_BYTES = 8192;
const ADMIN_SESSION_SECONDS = 8 * 60 * 60;

const ADMIN_COOKIE = "__Host-surl_session";

const SHORT_KEY_RE = /^[A-Za-z0-9_-]{1,40}$/;
const HASH_KEY_RE = /^[a-f0-9]{64}$/i;

const RESERVED_KEYS = new Set([
  "admin",
  "api",
  "favicon.ico"
]);

const RANDOM_ALPHABET =
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

const ALLOWED_EXPIRATIONS = new Set([
  0,
  86400,
  2592000
]);


// ============================================================
// RESPONSE HELPERS
// ============================================================

function securityHeaders(extra = {}) {
  return {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    ...extra
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: securityHeaders({
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store, max-age=0",
      ...extraHeaders
    })
  });
}

function textResponse(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: securityHeaders({
      "Content-Type": "text/plain; charset=UTF-8",
      "Cache-Control": "no-store, max-age=0",
      ...extraHeaders
    })
  });
}

function htmlResponse(markup, allowTurnstile = false) {
  const random = new Uint8Array(18);

  crypto.getRandomValues(random);

  const nonce = bytesToBase64Url(random);

  const body = markup.replace(
    /<script>/g,
    `<script nonce="${nonce}">`
  );

  const scriptSources = allowTurnstile
    ? `'self' 'nonce-${nonce}' https://challenges.cloudflare.com`
    : `'self' 'nonce-${nonce}'`;

  const connectSources = allowTurnstile
    ? "'self' https://challenges.cloudflare.com"
    : "'self'";

  const frameSources = allowTurnstile
    ? "https://challenges.cloudflare.com"
    : "'none'";

  return new Response(body, {
    headers: securityHeaders({
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store, max-age=0",

      "Content-Security-Policy":
        `default-src 'self'; ` +
        `script-src ${scriptSources}; ` +
        `style-src 'self' 'unsafe-inline'; ` +
        `frame-src ${frameSources}; ` +
        `connect-src ${connectSources}; ` +
        `img-src 'self' data:; ` +
        `base-uri 'none'; ` +
        `form-action 'self'; ` +
        `frame-ancestors 'none'; ` +
        `object-src 'none'`
    })
  });
}


// ============================================================
// KEY VALIDATION
// ============================================================

function isSystemKey(key) {
  return typeof key === "string" && /^SYS_/i.test(key);
}

function isValidNewKey(key) {
  if (
    typeof key !== "string" ||
    !SHORT_KEY_RE.test(key)
  ) {
    return false;
  }

  if (RESERVED_KEYS.has(key.toLowerCase())) {
    return false;
  }

  if (isSystemKey(key) || HASH_KEY_RE.test(key)) {
    return false;
  }

  return true;
}


// ============================================================
// URL VALIDATION
// ============================================================

// Compatible with v2.4 URL normalization.
function legacyFixURL(input) {
  if (typeof input !== "string") {
    return null;
  }

  let value = input.trim();

  if (!value) {
    return null;
  }

  if (!/^https?:\/\//i.test(value)) {
    value = "https://" + value;
  }

  if (!value.includes(".")) {
    return null;
  }

  return value;
}


// Canonical URL validation for new links.
function fixURL(input) {
  if (typeof input !== "string") {
    return null;
  }

  const value = input.trim();

  if (!value || value.length > 2048) {
    return null;
  }

  const legacy = legacyFixURL(value);

  if (!legacy) {
    return null;
  }

  try {
    const parsed = new URL(legacy);

    if (
      parsed.protocol !== "https:" &&
      parsed.protocol !== "http:"
    ) {
      return null;
    }

    if (
      !parsed.hostname ||
      parsed.username ||
      parsed.password
    ) {
      return null;
    }

    if (parsed.hostname.includes(" ")) {
      return null;
    }

    return parsed.href;

  } catch {
    return null;
  }
}


// ============================================================
// HASH AND RANDOM KEY
// ============================================================

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(
    new Uint8Array(digest),
    b => b.toString(16).padStart(2, "0")
  ).join("");
}

function randomShortKey(length = 10) {
  let out = "";

  const limit =
    Math.floor(256 / RANDOM_ALPHABET.length) *
    RANDOM_ALPHABET.length;

  const bytes = new Uint8Array(
    Math.max(16, length * 2)
  );

  while (out.length < length) {
    crypto.getRandomValues(bytes);

    for (const byte of bytes) {
      if (byte >= limit) {
        continue;
      }

      out += RANDOM_ALPHABET[
        byte % RANDOM_ALPHABET.length
      ];

      if (out.length === length) {
        break;
      }
    }
  }

  return out;
}


// ============================================================
// BASE64URL / SESSION
// ============================================================

function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized +
    "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);

  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }

  return out;
}

async function hmacSignature(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return bytesToBase64Url(
    new Uint8Array(signature)
  );
}

async function createSessionToken(secret) {
  const now = Math.floor(Date.now() / 1000);

  const random = new Uint8Array(12);

  crypto.getRandomValues(random);

  const payload = bytesToBase64Url(
    new TextEncoder().encode(
      JSON.stringify({
        v: 1,
        iat: now,
        exp: now + ADMIN_SESSION_SECONDS,
        nonce: bytesToBase64Url(random)
      })
    )
  );

  return payload + "." +
    await hmacSignature(secret, payload);
}

async function verifySessionToken(secret, token) {
  if (
    !secret ||
    typeof token !== "string" ||
    token.length > 2048
  ) {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  try {
    const expected = await hmacSignature(
      secret,
      parts[0]
    );

    if (expected !== parts[1]) {
      return false;
    }

    const payload = JSON.parse(
      new TextDecoder().decode(
        base64UrlToBytes(parts[0])
      )
    );

    const now = Math.floor(Date.now() / 1000);

    return payload &&
      payload.v === 1 &&
      Number.isInteger(payload.exp) &&
      payload.exp > now &&
      Number.isInteger(payload.iat) &&
      payload.iat <= now + 60 &&
      payload.exp - payload.iat <= ADMIN_SESSION_SECONDS;

  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const index = part.indexOf("=");

    if (index < 0) {
      continue;
    }

    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }

  return "";
}

function sessionCookie(token) {
  return `${ADMIN_COOKIE}=${token}; Path=/; Max-Age=${ADMIN_SESSION_SECONDS}; Secure; HttpOnly; SameSite=Strict`;
}

function clearSessionCookie() {
  return `${ADMIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;
}


// ============================================================
// ADMIN AUTHENTICATION
// ============================================================

function sameOriginMutation(request) {
  const origin = request.headers.get("Origin");

  if (origin) {
    try {
      return new URL(origin).origin ===
        new URL(request.url).origin;
    } catch {
      return false;
    }
  }

  return request.headers.get("Sec-Fetch-Site") !== "cross-site";
}

async function isAdmin(request, env) {
  if (!env.ADMIN_PASS) {
    return false;
  }

  const token = getCookie(request, ADMIN_COOKIE);

  if (
    token &&
    await verifySessionToken(env.ADMIN_PASS, token)
  ) {
    return true;
  }

  // Backwards compatibility for v2.4/v2.5 admin clients.
  return request.headers.get("Authorization") ===
    env.ADMIN_PASS;
}


// ============================================================
// REQUEST BODY LIMIT
// ============================================================

async function readJsonLimited(
  request,
  maxBytes = MAX_BODY_BYTES
) {
  const contentLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (
    Number.isFinite(contentLength) &&
    contentLength > maxBytes
  ) {
    return {
      ok: false,
      status: 413,
      error: "Payload Too Large"
    };
  }

  if (!request.body) {
    return {
      ok: false,
      status: 400,
      error: "Missing request body"
    };
  }

  const reader = request.body.getReader();

  const chunks = [];

  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        break;
      }

      total += value.byteLength;

      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {}

        return {
          ok: false,
          status: 413,
          error: "Payload Too Large"
        };
      }

      chunks.push(value);
    }

  } finally {
    try {
      reader.releaseLock();
    } catch {}
  }

  const bytes = new Uint8Array(total);

  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return {
      ok: true,
      data: JSON.parse(
        new TextDecoder().decode(bytes)
      )
    };

  } catch {
    return {
      ok: false,
      status: 400,
      error: "Invalid JSON"
    };
  }
}


// ============================================================
// RATE LIMITING
// ============================================================

async function checkRateLimit(binding, key) {
  if (
    !binding ||
    typeof binding.limit !== "function"
  ) {
    return {
      configured: false,
      allowed: true
    };
  }

  try {
    const result = await binding.limit({ key });

    return {
      configured: true,
      allowed: result.success === true
    };

  } catch (error) {
    console.error("Rate limiter binding error:", error);

    return {
      configured: true,
      allowed: false,
      unavailable: true
    };
  }
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}


// ============================================================
// TURNSTILE
// ============================================================

async function getTurnstileSecret(env) {
  const dedicated =
    typeof env.TURNSTILE_SECRET === "string"
      ? env.TURNSTILE_SECRET.trim()
      : "";

  if (dedicated) {
    return dedicated;
  }

  // Legacy compatibility with v2.4 / v2.5.
  return (
    await env.LINKS.get(
      "SYS_SS",
      { cacheTtl: KV_CACHE_TTL_SECONDS }
    )
  ) || "";
}

async function getTurnstileSecretSource(env) {
  const dedicated =
    typeof env.TURNSTILE_SECRET === "string"
      ? env.TURNSTILE_SECRET.trim()
      : "";

  if (dedicated) {
    return "worker";
  }

  const legacy =
    (await env.LINKS.get(
      "SYS_SS",
      { cacheTtl: KV_CACHE_TTL_SECONDS }
    )) || "";

  return legacy ? "legacy" : "missing";
}

async function verifyTurnstile(request, env, token) {
  const secret = await getTurnstileSecret(env);

  if (!secret) {
    return {
      ok: false,
      status: 503,
      error: "Turnstile Secret 未配置"
    };
  }

  if (
    typeof token !== "string" ||
    token.length > 2048 ||
    !token.trim()
  ) {
    return {
      ok: false,
      status: 403,
      error: "请先完成验证码"
    };
  }

  const form = new FormData();

  form.append("secret", secret);
  form.append("response", token);

  const ip = clientIp(request);

  if (ip !== "unknown") {
    form.append("remoteip", ip);
  }

  let result;

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: form,
        signal: AbortSignal.timeout(5000)
      }
    );

    if (!response.ok) {
      return {
        ok: false,
        status: 502,
        error: "验证码服务暂时不可用"
      };
    }

    result = await response.json();

  } catch (error) {
    console.error("Turnstile Siteverify error:", error);

    return {
      ok: false,
      status: 502,
      error: "验证码服务暂时不可用"
    };
  }

  if (!result || result.success !== true) {
    return {
      ok: false,
      status: 403,
      error: "验证码验证失败，请重新验证"
    };
  }

  const expectedHost =
    new URL(request.url).hostname.toLowerCase();

  if (
    !result.hostname ||
    String(result.hostname).toLowerCase() !== expectedHost
  ) {
    return {
      ok: false,
      status: 403,
      error: "验证码域名不匹配"
    };
  }

  if (result.action !== "create_short_url") {
    return {
      ok: false,
      status: 403,
      error: "验证码 Action 不匹配"
    };
  }

  return { ok: true };
}


// ============================================================
// CACHE HELPERS
// ============================================================

function cacheKeyRequest(origin, key) {
  // The public short-link URL is the cache key.
  // Compatible with old v2.4 entries without query strings.
  return new Request(
    new URL(
      "/" + encodeURIComponent(key),
      origin
    ).toString(),
    { method: "GET" }
  );
}

async function cacheTagForKey(key) {
  return "surl-" + await sha256(key);
}

function clientRedirectResponse(
  target,
  cacheState = "BYPASS"
) {
  return new Response(null, {
    status: 302,
    headers: securityHeaders({
      Location: target,
      "Cache-Control": "no-store, max-age=0",
      "X-ShortURL-Cache": cacheState
    })
  });
}


// ============================================================
// GLOBAL CACHE PURGE
// Requires:
//   CF_ZONE_ID
//   CF_PURGE_TOKEN
// ============================================================

async function purgeGlobalTag(env, tag) {
  if (!env.CF_ZONE_ID || !env.CF_PURGE_TOKEN) {
    return {
      global: false,
      reason: "CF_PURGE_TOKEN 或 CF_ZONE_ID 未配置"
    };
  }

  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(env.CF_ZONE_ID)}/purge_cache`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.CF_PURGE_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          tags: [tag]
        }),
        signal: AbortSignal.timeout(8000)
      }
    );

    const data = await response.json().catch(() => null);

    if (
      !response.ok ||
      !data ||
      data.success !== true
    ) {
      console.error(
        "Global cache purge failed:",
        response.status,
        data
      );

      return {
        global: false,
        reason: "Cloudflare 全局标签缓存清理失败"
      };
    }

    return { global: true };

  } catch (error) {
    console.error(
      "Global cache purge request failed:",
      error
    );

    return {
      global: false,
      reason: "Cloudflare 全局缓存清理请求失败"
    };
  }
}

async function purgeGlobalLegacyUrl(
  env,
  origin,
  key
) {
  if (!env.CF_ZONE_ID || !env.CF_PURGE_TOKEN) {
    return {
      global: false,
      reason: "CF_PURGE_TOKEN 或 CF_ZONE_ID 未配置"
    };
  }

  try {
    const legacyUrl = new URL(
      "/" + encodeURIComponent(key),
      origin
    ).toString();

    const response = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(env.CF_ZONE_ID)}/purge_cache`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.CF_PURGE_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          files: [legacyUrl]
        }),
        signal: AbortSignal.timeout(8000)
      }
    );

    const data = await response.json().catch(() => null);

    if (
      !response.ok ||
      !data ||
      data.success !== true
    ) {
      console.error(
        "Legacy URL cache purge failed:",
        response.status,
        data
      );

      return {
        global: false,
        reason: "旧版 URL 缓存清理失败"
      };
    }

    return { global: true };

  } catch (error) {
    console.error(
      "Legacy URL purge request failed:",
      error
    );

    return {
      global: false,
      reason: "旧版 URL 缓存清理请求失败"
    };
  }
}


// ============================================================
// HASH INDEX CLEANUP
// ============================================================

async function cleanupUrlIndexes(
  env,
  key,
  storedUrl
) {
  const candidates = new Set([storedUrl]);

  const canonical = fixURL(storedUrl);
  const legacy = legacyFixURL(storedUrl);

  if (canonical) {
    candidates.add(canonical);
  }

  if (legacy) {
    candidates.add(legacy);
  }

  for (const candidate of candidates) {
    const hash = await sha256(candidate);

    const mapped = await env.LINKS.get(
      hash,
      { cacheTtl: KV_CACHE_TTL_SECONDS }
    );

    if (mapped === key) {
      await env.LINKS.delete(hash);
    }
  }
}


// ============================================================
// ADMIN PANEL
// ============================================================

const ADMIN_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Short URL Manager</title>

<style>
:root{
  color-scheme:light;
  --bg:#f3f6fb;
  --card:#fff;
  --text:#172033;
  --muted:#718096;
  --line:#e7ecf3;
  --blue:#2563eb;
  --blue2:#1d4ed8;
  --red:#dc2626;
  --green:#059669;
  --amber:#b45309;
  --shadow:0 8px 28px rgba(23,32,51,.06)
}

*{box-sizing:border-box}

body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif
}

button,input,select{font:inherit}
button{cursor:pointer}

.shell{
  max-width:1180px;
  margin:0 auto;
  padding:24px
}

.topbar{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  margin-bottom:22px
}

.brand{
  display:flex;
  align-items:center;
  gap:12px
}

.logo{
  width:42px;
  height:42px;
  border-radius:13px;
  background:linear-gradient(135deg,#2563eb,#60a5fa);
  display:grid;
  place-items:center;
  color:#fff;
  font-size:21px;
  font-weight:800;
  box-shadow:0 6px 16px rgba(37,99,235,.22)
}

.brand h1{
  font-size:19px;
  margin:0;
  letter-spacing:-.3px
}

.brand p{
  font-size:12px;
  color:var(--muted);
  margin:4px 0 0
}

.top-actions{
  display:flex;
  align-items:center;
  gap:10px
}

.version{
  border:1px solid #bfdbfe;
  background:#eff6ff;
  color:#1d4ed8;
  padding:6px 10px;
  border-radius:999px;
  font-size:12px;
  font-weight:700
}

.btn{
  border:1px solid var(--line);
  background:#fff;
  color:var(--text);
  padding:9px 13px;
  border-radius:9px;
  font-weight:650;
  font-size:13px;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:7px
}

.btn:hover{background:#f8fafc}

.btn-primary{
  background:var(--blue);
  color:#fff;
  border-color:var(--blue)
}

.btn-primary:hover{background:var(--blue2)}

.btn-danger{
  color:var(--red);
  border-color:#fecaca;
  background:#fff
}

.btn-quiet{background:transparent}

.btn:disabled{
  opacity:.55;
  cursor:not-allowed
}

.grid-stats{
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:14px;
  margin-bottom:18px
}

.stat,.panel,.login-card{
  background:var(--card);
  border:1px solid var(--line);
  border-radius:15px;
  box-shadow:var(--shadow)
}

.stat{padding:17px 18px}

.stat-label{
  color:var(--muted);
  font-size:12px;
  font-weight:650
}

.stat-value{
  font-size:26px;
  font-weight:800;
  letter-spacing:-.8px;
  margin-top:7px
}

.stat-note{
  font-size:11px;
  color:var(--muted);
  margin-top:4px
}

.panel{
  padding:20px;
  margin-bottom:18px
}

.panel-head{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  margin-bottom:16px
}

.panel-head h2{
  font-size:16px;
  margin:0
}

.subtle{
  font-size:12px;
  color:var(--muted)
}

.toolbar{
  display:grid;
  grid-template-columns:minmax(220px,1fr) 170px 170px auto;
  gap:10px;
  margin-bottom:14px
}

.control{
  width:100%;
  border:1px solid #dce3ed;
  background:#fff;
  border-radius:9px;
  padding:10px 12px;
  color:var(--text);
  outline:none;
  min-height:40px
}

.control:focus{
  border-color:#93b4ff;
  box-shadow:0 0 0 3px rgba(37,99,235,.09)
}

.search-wrap{position:relative}

.search-wrap input{padding-left:36px}

.search-icon{
  position:absolute;
  left:12px;
  top:11px;
  color:#94a3b8;
  font-size:15px
}

.list-meta{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  margin:7px 0 12px;
  color:var(--muted);
  font-size:12px
}

.cards{
  display:grid;
  grid-template-columns:1fr;
  gap:10px
}

.link-card{
  border:1px solid var(--line);
  border-radius:12px;
  background:#fff;
  padding:15px 16px;
  display:grid;
  grid-template-columns:minmax(180px,1fr) minmax(240px,1.5fr) minmax(135px,.75fr) auto;
  gap:15px;
  align-items:center
}

.link-main{min-width:0}

.key{
  font-size:14px;
  font-weight:800;
  letter-spacing:.15px;
  overflow-wrap:anywhere
}

.short{
  font-size:12px;
  color:#2563eb;
  overflow-wrap:anywhere;
  margin-top:5px
}

.target{min-width:0}

.target a,.target span{
  font-size:13px;
  color:#475569;
  overflow-wrap:anywhere;
  text-decoration:none
}

.target a:hover{
  text-decoration:underline;
  color:var(--blue)
}

.target-label,.field-label{
  display:block;
  font-size:10px;
  color:#94a3b8;
  text-transform:uppercase;
  letter-spacing:.6px;
  margin-bottom:5px;
  font-weight:750
}

.dates{
  font-size:12px;
  color:#64748b;
  line-height:1.65
}

.pill{
  display:inline-flex;
  align-items:center;
  gap:5px;
  border-radius:999px;
  padding:5px 8px;
  font-size:11px;
  font-weight:750;
  white-space:nowrap
}

.pill-green{background:#ecfdf5;color:#047857}
.pill-blue{background:#eff6ff;color:#1d4ed8}
.pill-amber{background:#fffbeb;color:#a16207}
.pill-gray{background:#f1f5f9;color:#64748b}

.actions{
  display:flex;
  gap:6px;
  justify-content:flex-end
}

.icon-btn{
  width:34px;
  height:34px;
  border:1px solid var(--line);
  background:#fff;
  border-radius:8px;
  color:#64748b;
  display:grid;
  place-items:center;
  font-size:14px
}

.icon-btn:hover{
  background:#f8fafc;
  color:var(--blue)
}

.icon-btn.delete:hover{
  color:var(--red);
  border-color:#fecaca
}

.pagination{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  margin-top:16px
}

.page-actions{
  display:flex;
  gap:8px
}

.empty{
  border:1px dashed #cbd5e1;
  border-radius:12px;
  padding:34px 15px;
  text-align:center;
  color:var(--muted);
  font-size:13px
}

.message{
  margin-top:10px;
  font-size:12px;
  color:var(--muted);
  line-height:1.55
}

.message.error{color:var(--red)}
.message.success{color:var(--green)}

.settings-grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:16px
}

.setting label{
  display:block;
  font-size:12px;
  font-weight:700;
  margin-bottom:7px
}

.help{
  font-size:11px;
  color:var(--muted);
  line-height:1.55;
  margin-top:6px
}

.toggle-row{
  display:flex;
  align-items:center;
  gap:9px;
  font-size:13px;
  font-weight:650
}

.toggle-row input{
  width:17px;
  height:17px;
  accent-color:var(--blue)
}

.login-wrap{
  min-height:78vh;
  display:grid;
  place-items:center
}

.login-card{
  padding:28px;
  width:min(390px,100%)
}

.login-card h2{
  margin:0 0 6px;
  font-size:21px
}

.login-card p{
  color:var(--muted);
  font-size:13px;
  line-height:1.6;
  margin:0 0 20px
}

.login-card label{
  display:block;
  font-size:12px;
  font-weight:700;
  margin-bottom:7px
}

.login-card input{margin-bottom:12px}

.footer{
  text-align:center;
  color:#94a3b8;
  font-size:11px;
  padding:10px 0 24px
}

@media(max-width:900px){
  .link-card{
    grid-template-columns:minmax(150px,1fr) minmax(200px,1.3fr) auto
  }

  .dates{grid-column:1/3}

  .actions{
    grid-column:3;
    grid-row:1/3
  }

  .grid-stats{grid-template-columns:repeat(2,1fr)}

  .toolbar{grid-template-columns:1fr 1fr}

  .search-wrap{grid-column:1/3}
}

@media(max-width:600px){
  .shell{padding:14px}
  .topbar{align-items:flex-start}
  .brand h1{font-size:16px}
  .brand p{font-size:10px}
  .top-actions{gap:6px}
  .version{display:none}
  .grid-stats{gap:9px}
  .stat{padding:13px}
  .stat-value{font-size:22px}
  .panel{padding:14px}
  .toolbar{grid-template-columns:1fr 1fr}
  .search-wrap{grid-column:1/3}

  .link-card{
    grid-template-columns:1fr auto;
    gap:10px;
    padding:13px
  }

  .link-main{grid-column:1}

  .target{
    grid-column:1/3;
    grid-row:2
  }

  .dates{
    grid-column:1/2;
    grid-row:3
  }

  .actions{
    grid-column:2;
    grid-row:1/4;
    align-self:center;
    flex-direction:column
  }

  .pagination{
    align-items:flex-start;
    flex-direction:column
  }

  .settings-grid{grid-template-columns:1fr}

  .panel-head{
    align-items:flex-start;
    flex-direction:column
  }
}
</style>
</head>

<body>

<div id="login-view" class="shell login-wrap" style="display:none">
  <div class="login-card">

    <div class="brand" style="margin-bottom:22px">
      <div class="logo">↗</div>
      <div>
        <h1>Short URL Manager</h1>
        <p>SECURE ADMINISTRATION</p>
      </div>
    </div>

    <h2>管理员登录</h2>

    <p>请输入管理员密码以管理短链接和验证码设置。</p>

    <form id="login-form">
      <label for="login-pass">管理员密码</label>

      <input
        id="login-pass"
        class="control"
        type="password"
        autocomplete="current-password"
        required
      >

      <button
        class="btn btn-primary"
        style="width:100%"
        type="submit"
      >
        登录管理后台
      </button>
    </form>

    <div
      id="login-message"
      class="message error"
      aria-live="polite"
    ></div>

  </div>
</div>


<div id="app-view" class="shell" style="display:none">

  <header class="topbar">

    <div class="brand">
      <div class="logo">↗</div>
      <div>
        <h1>Short URL Manager</h1>
        <p>短链接管理控制台</p>
      </div>
    </div>

    <div class="top-actions">
      <span class="version">v2.6.0</span>

      <button id="refresh-btn" class="btn">
        ↻ 刷新
      </button>

      <button id="logout-btn" class="btn btn-danger">
        退出登录
      </button>
    </div>

  </header>


  <section class="grid-stats">

    <div class="stat">
      <div class="stat-label">当前页短链</div>
      <div id="stat-total" class="stat-value">—</div>
      <div class="stat-note">本页读取到的有效记录</div>
    </div>

    <div class="stat">
      <div class="stat-label">永久有效</div>
      <div id="stat-permanent" class="stat-value">—</div>
      <div class="stat-note">未设置 KV 到期时间</div>
    </div>

    <div class="stat">
      <div class="stat-label">限时有效</div>
      <div id="stat-limited" class="stat-value">—</div>
      <div class="stat-note">有明确到期时间的记录</div>
    </div>

    <div class="stat">
      <div class="stat-label">即将到期</div>
      <div id="stat-soon" class="stat-value">—</div>
      <div class="stat-note">24 小时内到期</div>
    </div>

  </section>


  <section class="panel">

    <div class="panel-head">
      <div>
        <h2>链接列表</h2>
        <div class="subtle" style="margin-top:5px">
          搜索、筛选和排序作用于当前加载页
        </div>
      </div>

      <span id="page-count" class="subtle">
        加载中...
      </span>
    </div>


    <div class="toolbar">

      <div class="search-wrap">
        <span class="search-icon">⌕</span>

        <input
          id="search-input"
          class="control"
          type="search"
          placeholder="搜索短码、域名或目标 URL"
        >
      </div>

      <select id="filter-select" class="control">
        <option value="all">全部链接</option>
        <option value="permanent">永久有效</option>
        <option value="limited">限时有效</option>
        <option value="soon">24 小时内到期</option>
        <option value="expired">已到期（等待清理）</option>
      </select>

      <select id="sort-select" class="control">
        <option value="key-asc">短码：升序</option>
        <option value="key-desc">短码：降序</option>
        <option value="created-desc">创建时间：新到旧</option>
        <option value="created-asc">创建时间：旧到新</option>
        <option value="expiry-asc">到期时间：近到远</option>
        <option value="domain-asc">目标域名：A-Z</option>
      </select>

      <button id="clear-filter-btn" class="btn">
        清除筛选
      </button>

    </div>


    <div class="list-meta">
      <span id="visible-count">—</span>
      <span>
        永久短链缓存 24 小时；限时短链缓存不超过到期时间
      </span>
    </div>


    <div id="link-list" class="cards">
      <div class="empty">正在读取 KV 数据...</div>
    </div>


    <div class="pagination">

      <span id="pagination-info" class="subtle">—</span>

      <div class="page-actions">
        <button id="prev-btn" class="btn" disabled>
          上一页
        </button>

        <button id="next-btn" class="btn btn-primary" disabled>
          下一页
        </button>
      </div>

    </div>


    <div
      id="list-message"
      class="message"
      aria-live="polite"
    ></div>

  </section>


  <section class="panel">

    <div class="panel-head">
      <div>
        <h2>安全与验证码设置</h2>
        <div class="subtle" style="margin-top:5px">
          Turnstile 可以单独开启或关闭
        </div>
      </div>
    </div>


    <div class="settings-grid">

      <div class="setting">
        <label class="toggle-row">
          <input id="captcha-enabled" type="checkbox">
          开启 Turnstile 验证码
        </label>

        <div class="help">
          关闭时创建短链不要求验证码，也不要求配置 Secret。
        </div>
      </div>


      <div class="setting">

        <label for="site-key">
          SiteKey（公开站点密钥）
        </label>

        <input
          id="site-key"
          class="control"
          type="text"
          autocomplete="off"
          placeholder="Cloudflare Turnstile SiteKey"
        >

        <div class="help">
          SiteKey 来自 Turnstile Widget；
          Secret 仅保存在 Worker Secret 中，不会显示在后台。
        </div>

      </div>

    </div>


    <div id="secret-status" class="message"></div>

    <button
      id="save-config-btn"
      class="btn btn-primary"
      style="margin-top:12px"
    >
      保存设置
    </button>

    <div
      id="config-message"
      class="message"
      aria-live="polite"
    ></div>

  </section>


  <div class="footer">
    Cloudflare Worker Short URL · v2.6.0 · Data stays in your existing KV namespace
  </div>

</div>


<script>

const $ = id => document.getElementById(id);

// Remove the legacy v2.4/v2.5 plaintext admin password from localStorage.
try {
  localStorage.removeItem("ADMIN_PASS");
} catch {}


let currentLinks = [];

let pageStack = [""];

let pageIndex = 0;

let currentCursor = "";

let nextCursor = "";

let loading = false;


function safeUrl(value) {
  try {
    const u = new URL(value);

    return (
      u.protocol === "http:" ||
      u.protocol === "https:"
    ) ? u.href : null;

  } catch {
    return null;
  }
}


function formatDate(value) {
  if (!value) {
    return "未记录";
  }

  const d = new Date(value);

  if (Number.isNaN(d.getTime())) {
    return "未记录";
  }

  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(d);
}


function expiryInfo(item) {
  if (!item.expiresAt) {
    return {
      label: "永久有效",
      kind: "permanent",
      sort: Number.MAX_SAFE_INTEGER
    };
  }

  const remain = item.expiresAt - Date.now();

  if (remain <= 0) {
    return {
      label: "已到期（等待 KV 清理）",
      kind: "expired",
      sort: item.expiresAt
    };
  }

  const hours = Math.ceil(remain / 3600000);

  const days = Math.ceil(remain / 86400000);

  if (hours <= 24) {
    return {
      label: "剩余 " + hours + " 小时",
      kind: "soon",
      sort: item.expiresAt
    };
  }

  return {
    label: "剩余 " + days + " 天",
    kind: "limited",
    sort: item.expiresAt
  };
}


async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: {
      ...(options.headers || {})
    }
  });

  let data = {};

  try {
    data = await response.json();
  } catch {}


  if (response.status === 401) {
    showLogin("登录已过期，请重新登录。");
    throw new Error("登录已过期");
  }

  if (!response.ok) {
    throw new Error(
      data.error || ("HTTP " + response.status)
    );
  }

  return {
    data,
    response
  };
}


function showLogin(message = "") {
  $("app-view").style.display = "none";
  $("login-view").style.display = "grid";
  $("login-message").textContent = message;
}

function showApp() {
  $("login-view").style.display = "none";
  $("app-view").style.display = "block";
}

function setMessage(id, message, type = "") {
  $(id).textContent = message;

  $(id).className =
    "message" + (type ? " " + type : "");
}


// ============================================================
// DASHBOARD STATISTICS
// ============================================================

function renderStats(items) {
  const permanent =
    items.filter(x => !x.expiresAt).length;

  const limited =
    items.filter(x => x.expiresAt).length;

  const soon = items.filter(
    x =>
      x.expiresAt &&
      x.expiresAt > Date.now() &&
      x.expiresAt - Date.now() <= 86400000
  ).length;

  $("stat-total").textContent = items.length;
  $("stat-permanent").textContent = permanent;
  $("stat-limited").textContent = limited;
  $("stat-soon").textContent = soon;
}


function createElement(tag, className, text) {
  const el = document.createElement(tag);

  if (className) {
    el.className = className;
  }

  if (text !== undefined) {
    el.textContent = text;
  }

  return el;
}


// ============================================================
// LINK LIST RENDERING
// ============================================================

function renderLinks() {
  const query =
    $("search-input").value.trim().toLowerCase();

  const filter = $("filter-select").value;

  const sort = $("sort-select").value;


  let rows = currentLinks.filter(item => {
    const expiry = expiryInfo(item);

    const target =
      String(item.value || "").toLowerCase();

    const haystack = (
      String(item.name || "") +
      " " +
      target +
      " " +
      (safeUrl(item.value) || "")
    ).toLowerCase();


    if (query && !haystack.includes(query)) {
      return false;
    }

    if (
      filter === "permanent" &&
      expiry.kind !== "permanent"
    ) {
      return false;
    }

    if (
      filter === "limited" &&
      expiry.kind !== "limited" &&
      expiry.kind !== "soon"
    ) {
      return false;
    }

    if (
      filter === "soon" &&
      expiry.kind !== "soon"
    ) {
      return false;
    }

    if (
      filter === "expired" &&
      expiry.kind !== "expired"
    ) {
      return false;
    }

    return true;
  });


  rows.sort((a, b) => {
    const ea = expiryInfo(a);
    const eb = expiryInfo(b);

    switch (sort) {
      case "key-desc":
        return String(b.name).localeCompare(
          String(a.name)
        );

      case "created-desc":
        return (b.createdAt || 0) -
          (a.createdAt || 0);

      case "created-asc":
        return (a.createdAt || 0) -
          (b.createdAt || 0);

      case "expiry-asc":
        return ea.sort - eb.sort;

      case "domain-asc":
        return (
          safeUrl(a.value)
            ? new URL(a.value).hostname.toLowerCase()
            : ""
        ).localeCompare(
          safeUrl(b.value)
            ? new URL(b.value).hostname.toLowerCase()
            : ""
        );

      default:
        return String(a.name).localeCompare(
          String(b.name)
        );
    }
  });


  renderStats(currentLinks);

  $("visible-count").textContent =
    "显示 " + rows.length +
    " / 当前页 " + currentLinks.length + " 条";

  $("page-count").textContent =
    "当前页 " + currentLinks.length + " 条记录";

  $("pagination-info").textContent =
    "第 " + (pageIndex + 1) +
    " 页；KV 按游标分页，不进行全库扫描";

  $("prev-btn").disabled =
    pageIndex <= 0 || loading;

  $("next-btn").disabled =
    !nextCursor || loading;


  const container = $("link-list");

  container.replaceChildren();


  if (!rows.length) {
    container.appendChild(
      createElement(
        "div",
        "empty",
        currentLinks.length
          ? "当前页没有符合条件的短链。"
          : "当前页没有短链记录。"
      )
    );

    return;
  }


  for (const item of rows) {
    const card = createElement("article", "link-card");

    const main = createElement("div", "link-main");

    main.appendChild(
      createElement("span", "field-label", "SHORT CODE")
    );

    main.appendChild(
      createElement("div", "key", item.name)
    );

    const shortUrl =
      location.origin + "/" + encodeURIComponent(item.name);

    main.appendChild(
      createElement("div", "short", shortUrl)
    );


    const target = createElement("div", "target");

    target.appendChild(
      createElement("span", "target-label", "DESTINATION URL")
    );

    const validTarget = safeUrl(item.value);

    if (validTarget) {
      const anchor = createElement("a", "", item.value);

      anchor.href = validTarget;
      anchor.target = "_blank";
      anchor.rel = "noopener noreferrer";

      target.appendChild(anchor);

    } else {
      target.appendChild(
        createElement(
          "span",
          "",
          item.value || "（无目标 URL）"
        )
      );
    }


    const dates = createElement("div", "dates");

    dates.appendChild(
      createElement(
        "div",
        "",
        "创建：" + formatDate(item.createdAt)
      )
    );

    dates.appendChild(
      createElement(
        "div",
        "",
        "到期：" +
          (
            item.expiresAt
              ? formatDate(item.expiresAt)
              : "永久有效"
          )
      )
    );

    const exp = expiryInfo(item);

    const pill = createElement(
      "span",
      "pill " +
        (
          exp.kind === "permanent"
            ? "pill-green"
            : exp.kind === "soon" ||
              exp.kind === "expired"
              ? "pill-amber"
              : "pill-blue"
        ),
      exp.label
    );

    dates.appendChild(pill);


    const actions = createElement("div", "actions");


    // Copy short URL.
    const copyBtn = createElement(
      "button",
      "icon-btn",
      "⧉"
    );

    copyBtn.type = "button";
    copyBtn.title = "复制短链接";
    copyBtn.setAttribute(
      "aria-label",
      "复制短链接"
    );

    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(shortUrl);

        setMessage(
          "list-message",
          "短链接已复制：" + shortUrl,
          "success"
        );

      } catch {
        setMessage(
          "list-message",
          "复制失败，请手动复制：" + shortUrl,
          "error"
        );
      }
    });

    actions.appendChild(copyBtn);


    // Open original URL.
    const openBtn = createElement(
      "button",
      "icon-btn",
      "↗"
    );

    openBtn.type = "button";
    openBtn.title = "打开目标链接";
    openBtn.setAttribute(
      "aria-label",
      "打开目标链接"
    );

    openBtn.disabled = !validTarget;

    openBtn.addEventListener("click", () => {
      if (validTarget) {
        window.open(
          validTarget,
          "_blank",
          "noopener,noreferrer"
        );
      }
    });

    actions.appendChild(openBtn);


    // Delete short URL.
    const delBtn = createElement(
      "button",
      "icon-btn delete",
      "×"
    );

    delBtn.type = "button";
    delBtn.title = "删除短链接";
    delBtn.setAttribute(
      "aria-label",
      "删除短链接"
    );

    delBtn.addEventListener("click", () => {
      deleteLink(item.name);
    });

    actions.appendChild(delBtn);


    card.append(
      main,
      target,
      dates,
      actions
    );

    container.appendChild(card);
  }
}


// ============================================================
// ADMIN PAGE LOADING
// ============================================================

async function loadPage(cursor = "", push = true) {
  if (loading) {
    return;
  }

  loading = true;

  $("refresh-btn").disabled = true;
  $("prev-btn").disabled = true;
  $("next-btn").disabled = true;

  $("link-list").replaceChildren(
    createElement(
      "div",
      "empty",
      "正在读取 KV 数据..."
    )
  );

  try {
    const q = cursor
      ? "?cursor=" + encodeURIComponent(cursor)
      : "";

    const { data } = await api(
      "/admin/api/all" + q
    );

    currentLinks = Array.isArray(data.links)
      ? data.links
      : [];

    nextCursor = data.next || "";

    currentCursor = cursor;

    if (push) {
      pageStack = pageStack.slice(0, pageIndex + 1);
    }

    pageStack[pageIndex] = cursor;

    showApp();

    renderLinks();

    $("captcha-enabled").checked =
      data.cfg?.ce === "true";

    $("site-key").value =
      data.cfg?.sk || "";


    const source = data.cfg?.secretSource;

    setMessage(
      "secret-status",

      source === "worker"
        ? "Turnstile Secret：已使用 Worker Secret（不会发送到浏览器）。"
        : source === "legacy"
          ? "Turnstile Secret：目前使用旧 KV 后备密钥 SYS_SS，建议迁移到 Worker Secret。"
          : "Turnstile Secret：未配置；关闭验证码时不需要配置。"
    );


    setMessage(
      "list-message",

      data.rateLimitConfigured
        ? "创建接口 Rate Limiting binding 已启用。"
        : "未检测到 CREATE_LIMITER binding；请配置 Worker Rate Limiting 或 Cloudflare WAF 规则。"
    );

  } catch (error) {
    if (error.message !== "登录已过期") {
      setMessage(
        "list-message",
        "加载失败：" + error.message,
        "error"
      );
    }

  } finally {
    loading = false;

    $("refresh-btn").disabled = false;

    renderLinks();
  }
}


// ============================================================
// DELETE LINK
// ============================================================

async function deleteLink(key) {
  if (
    !confirm(
      "确定删除短链接「" +
      key +
      "」？此操作不可撤销。"
    )
  ) {
    return;
  }

  try {
    const { data } = await api(
      "/admin/api/delete",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ key })
      }
    );

    if (data.cachePurge === "global") {
      setMessage(
        "list-message",
        "短链已删除，Cloudflare 全局缓存清理请求已提交。",
        "success"
      );

    } else {
      setMessage(
        "list-message",
        "短链已删除；目前仅清理当前数据中心缓存。其他地区的 24 小时缓存可能在到期前继续生效。请配置 CF_ZONE_ID 和 CF_PURGE_TOKEN 实现全局清理。",
        "error"
      );
    }

    await loadPage(currentCursor, false);

  } catch (error) {
    setMessage(
      "list-message",
      "删除失败：" + error.message,
      "error"
    );
  }
}


// ============================================================
// ADMIN EVENT HANDLERS
// ============================================================

$("login-form").addEventListener(
  "submit",
  async event => {
    event.preventDefault();

    const password = $("login-pass").value;

    setMessage(
      "login-message",
      "正在验证..."
    );

    try {
      await api(
        "/admin/api/login",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ password })
        }
      );

      $("login-pass").value = "";

      pageStack = [""];
      pageIndex = 0;

      await loadPage("", false);

    } catch (error) {
      setMessage(
        "login-message",
        error.message,
        "error"
      );
    }
  }
);


$("logout-btn").addEventListener(
  "click",
  async () => {
    try {
      await api(
        "/admin/api/logout",
        { method: "POST" }
      );
    } catch {}

    showLogin("已退出登录。");
  }
);


$("refresh-btn").addEventListener(
  "click",
  () => loadPage(currentCursor, false)
);


$("prev-btn").addEventListener(
  "click",
  () => {
    if (pageIndex > 0) {
      pageIndex--;
      loadPage(pageStack[pageIndex], false);
    }
  }
);


$("next-btn").addEventListener(
  "click",
  () => {
    if (nextCursor) {
      pageIndex++;
      pageStack[pageIndex] = nextCursor;
      loadPage(nextCursor, false);
    }
  }
);


$("search-input").addEventListener(
  "input",
  renderLinks
);

$("filter-select").addEventListener(
  "change",
  renderLinks
);

$("sort-select").addEventListener(
  "change",
  renderLinks
);


$("clear-filter-btn").addEventListener(
  "click",
  () => {
    $("search-input").value = "";
    $("filter-select").value = "all";
    $("sort-select").value = "key-asc";

    renderLinks();
  }
);


$("save-config-btn").addEventListener(
  "click",
  async () => {
    setMessage(
      "config-message",
      "正在保存..."
    );

    try {
      await api(
        "/admin/api/config",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            ce: $("captcha-enabled").checked,
            sk: $("site-key").value.trim()
          })
        }
      );

      setMessage(
        "config-message",
        "配置保存成功。",
        "success"
      );

    } catch (error) {
      setMessage(
        "config-message",
        "保存失败：" + error.message,
        "error"
      );
    }
  }
);


// Check existing session on page load.
(async () => {
  try {
    const { data } = await api("/admin/api/all");

    showApp();

    currentLinks = data.links || [];

    nextCursor = data.next || "";

    renderLinks();

    $("captcha-enabled").checked =
      data.cfg?.ce === "true";

    $("site-key").value =
      data.cfg?.sk || "";

    const source = data.cfg?.secretSource;

    setMessage(
      "secret-status",

      source === "worker"
        ? "Turnstile Secret：已使用 Worker Secret（不会发送到浏览器）。"
        : source === "legacy"
          ? "Turnstile Secret：目前使用旧 KV 后备密钥 SYS_SS。"
          : "Turnstile Secret：未配置；关闭验证码时不需要配置。"
    );

  } catch {
    showLogin();
  }
})();

</script>
</body>
</html>`;


// ============================================================
// FRONTEND
// ============================================================

const INDEX_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Short URL</title>

<style>
*{box-sizing:border-box}

body{
  font-family:Arial,sans-serif;
  display:flex;
  justify-content:center;
  align-items:center;
  min-height:100vh;
  background:#f3f6fb;
  margin:0;
  padding:16px
}

.box{
  background:#fff;
  padding:28px;
  border-radius:14px;
  width:360px;
  max-width:100%;
  box-shadow:0 8px 28px rgba(23,32,51,.08)
}

h3{
  margin:0 0 18px;
  color:#172033
}

input,button,select{
  width:100%;
  padding:11px;
  margin:6px 0;
  box-sizing:border-box;
  font:inherit
}

input,select{
  border:1px solid #dce3ed;
  border-radius:8px
}

button{
  background:#2563eb;
  color:white;
  border:0;
  border-radius:8px;
  cursor:pointer;
  font-weight:700
}

button:hover{background:#1d4ed8}

button:disabled{
  opacity:.55;
  cursor:not-allowed
}

#result{
  word-break:break-all;
  color:#2563eb;
  font-weight:700;
  margin:14px 0
}

.note{
  font-size:12px;
  color:#64748b;
  line-height:1.5
}

#error{
  font-size:13px;
  color:#dc2626;
  white-space:pre-wrap
}
</style>

</head>

<body>

<div class="box">

  <h3>短链接生成</h3>

  <input
    id="url-input"
    type="text"
    placeholder="输入目标网址，例如 www.example.com"
    autocomplete="url"
  >

  <input
    id="key-input"
    type="text"
    placeholder="自定义后缀（可选）"
    autocomplete="off"
    maxlength="40"
  >

  <select id="expire-input">
    <option value="0">永久有效</option>
    <option value="86400">1 天</option>
    <option value="2592000">30 天</option>
  </select>

  <div id="turnstile-container"></div>

  <div id="captcha-note" class="note"></div>

  <button id="create-button" type="button">
    生成短链
  </button>

  <p id="result"></p>

  <div id="error"></div>

  <button id="copy-button" type="button">
    复制短链接
  </button>

</div>


<script>

let captchaEnabled = false;

let turnstileToken = "";

let turnstileWidgetId = null;

let siteKey = "";

const byId = id => document.getElementById(id);


function setError(message) {
  byId("error").textContent = message || "";
}


function resetCaptcha() {
  turnstileToken = "";

  if (
    captchaEnabled &&
    turnstileWidgetId !== null &&
    window.turnstile
  ) {
    window.turnstile.reset(turnstileWidgetId);

    byId("create-button").disabled = true;
  }
}


// ============================================================
// FRONTEND INITIALIZATION
// ============================================================

async function init() {
  try {
    const response = await fetch(
      "/api/ui-cfg",
      { cache: "no-store" }
    );

    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const cfg = await response.json();

    captchaEnabled = cfg.ce === "true";

    siteKey = cfg.sk || "";

    if (!captchaEnabled) {
      return;
    }

    byId("create-button").disabled = true;

    if (!siteKey) {
      byId("captcha-note").textContent =
        "验证码配置不完整，请联系管理员。";

      return;
    }

    const script = document.createElement("script");

    script.src =
      "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

    script.async = true;
    script.defer = true;


    script.onload = () => {
      if (!window.turnstile) {
        byId("captcha-note").textContent =
          "验证码组件加载失败，请刷新页面。";

        return;
      }

      turnstileWidgetId = window.turnstile.render(
        byId("turnstile-container"),
        {
          sitekey: siteKey,
          action: "create_short_url",

          callback: token => {
            turnstileToken = token;

            byId("create-button").disabled = false;

            byId("captcha-note").textContent = "";
          },

          "expired-callback": () => {
            turnstileToken = "";

            byId("create-button").disabled = true;

            byId("captcha-note").textContent =
              "验证码已过期，请重新验证。";
          },

          "error-callback": () => {
            turnstileToken = "";

            byId("create-button").disabled = true;

            byId("captcha-note").textContent =
              "验证码验证失败，请刷新重试。";
          }
        }
      );
    };


    script.onerror = () => {
      byId("captcha-note").textContent =
        "验证码脚本加载失败，请检查网络后刷新。";
    };

    document.head.appendChild(script);

  } catch (error) {
    console.error("UI config error:", error);
  }
}


// ============================================================
// CREATE SHORT URL
// ============================================================

async function createShortUrl() {
  const url = byId("url-input").value.trim();

  const key = byId("key-input").value.trim();

  if (!url) {
    alert("请输入目标网址");
    return;
  }

  if (captchaEnabled && !turnstileToken) {
    alert("请先完成验证码");
    return;
  }

  byId("create-button").disabled = true;

  byId("result").textContent = "正在生成...";

  setError("");

  try {
    const response = await fetch(
      "/api/create",
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json"
        },

        body: JSON.stringify({
          url,
          key,
          expire: byId("expire-input").value,
          token: turnstileToken
        })
      }
    );

    const data = await response.json().catch(
      () => ({})
    );

    if (!response.ok || !data.key) {
      byId("result").textContent = "";

      setError(
        data.error ||
        ("生成失败（HTTP " + response.status + ")")
      );

      return;
    }

    byId("result").textContent =
      location.origin + data.key;

  } catch (error) {
    byId("result").textContent = "";

    setError("网络请求失败，请重试。");

  } finally {
    if (captchaEnabled) {
      resetCaptcha();
    } else {
      byId("create-button").disabled = false;
    }
  }
}


// ============================================================
// COPY RESULT
// ============================================================

async function copyResult() {
  const value = byId("result").textContent;

  if (
    !value ||
    value === "正在生成..."
  ) {
    return;
  }

  try {
    await navigator.clipboard.writeText(value);

    alert("已复制到剪贴板！");

  } catch {
    alert("复制失败，请手动复制短链接。");
  }
}


byId("create-button").addEventListener(
  "click",
  createShortUrl
);

byId("copy-button").addEventListener(
  "click",
  copyResult
);

init();

</script>
</body>
</html>`;


// ============================================================
// WORKER HANDLER
// ============================================================

export default {

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    let path;

    try {
      path = decodeURIComponent(
        url.pathname.slice(1)
      );

    } catch {
      return textResponse("Bad Request", 400);
    }


    try {
      if (!env.LINKS) {
        return json({
          error: "KV binding LINKS 未配置"
        }, 500);
      }


      // ========================================================
      // PUBLIC UI CONFIG
      // ========================================================

      if (url.pathname === "/api/ui-cfg") {
        if (request.method !== "GET") {
          return json(
            { error: "Method Not Allowed" },
            405,
            { Allow: "GET" }
          );
        }

        return json({
          ce: (
            await env.LINKS.get(
              "SYS_CE",
              { cacheTtl: KV_CACHE_TTL_SECONDS }
            )
          ) || "false",

          sk: (
            await env.LINKS.get(
              "SYS_SK",
              { cacheTtl: KV_CACHE_TTL_SECONDS }
            )
          ) || ""
        });
      }


      // ========================================================
      // ADMIN PAGE
      // ========================================================

      if (url.pathname === "/admin") {
        if (
          request.method !== "GET" &&
          request.method !== "HEAD"
        ) {
          return textResponse(
            "Method Not Allowed",
            405,
            { Allow: "GET, HEAD" }
          );
        }

        return htmlResponse(ADMIN_HTML, false);
      }


      // ========================================================
      // ADMIN APIs
      // ========================================================

      if (url.pathname.startsWith("/admin/api/")) {
        const endpoint = url.pathname;


        // ------------------------------------------------------
        // ADMIN LOGIN
        // ------------------------------------------------------

        if (endpoint === "/admin/api/login") {
          if (request.method !== "POST") {
            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "POST" }
            );
          }

          if (!sameOriginMutation(request)) {
            return json(
              { error: "Cross-origin request rejected" },
              403
            );
          }

          if (!env.ADMIN_PASS) {
            return json(
              { error: "ADMIN_PASS 未配置" },
              503
            );
          }


          const limited = await checkRateLimit(
            env.ADMIN_LOGIN_LIMITER,
            "login:" + clientIp(request)
          );

          if (limited.unavailable) {
            return json(
              { error: "登录限流服务暂时不可用" },
              503
            );
          }

          if (!limited.allowed) {
            return json(
              { error: "登录尝试过于频繁，请稍后再试" },
              429
            );
          }


          const parsed = await readJsonLimited(
            request,
            4096
          );

          if (!parsed.ok) {
            return json(
              { error: parsed.error },
              parsed.status
            );
          }

          const password =
            parsed.data &&
            typeof parsed.data.password === "string"
              ? parsed.data.password
              : "";

          if (
            !password ||
            password.length > 1024 ||
            password !== env.ADMIN_PASS
          ) {
            return json(
              { error: "管理员密码错误" },
              401
            );
          }


          const token = await createSessionToken(
            env.ADMIN_PASS
          );

          return json(
            {
              ok: true,
              expiresIn: ADMIN_SESSION_SECONDS
            },
            200,
            {
              "Set-Cookie": sessionCookie(token)
            }
          );
        }


        // ------------------------------------------------------
        // ADMIN LOGOUT
        // ------------------------------------------------------

        if (endpoint === "/admin/api/logout") {
          if (request.method !== "POST") {
            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "POST" }
            );
          }

          if (!sameOriginMutation(request)) {
            return json(
              { error: "Cross-origin request rejected" },
              403
            );
          }

          return json(
            { ok: true },
            200,
            {
              "Set-Cookie": clearSessionCookie()
            }
          );
        }


        // Remaining admin endpoints require a valid session,
        // or the legacy v2.4/v2.5 Authorization header.
        if (!(await isAdmin(request, env))) {
          return json(
            { error: "Unauthorized" },
            401
          );
        }


        // ------------------------------------------------------
        // ADMIN LIST
        // ------------------------------------------------------

        if (endpoint === "/admin/api/all") {
          if (request.method !== "GET") {
            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "GET" }
            );
          }

          const cursor =
            url.searchParams.get("cursor") || undefined;

          const list = await env.LINKS.list({
            limit: 100,
            ...(cursor ? { cursor } : {})
          });


          // Filter system keys and SHA-256 indexes.
          const visible = list.keys.filter(item =>
            !isSystemKey(item.name) &&
            !HASH_KEY_RE.test(item.name) &&
            item.name.length <= 512
          );


          const links = await Promise.all(
            visible.map(async item => {
              const value = await env.LINKS.get(
                item.name,
                { cacheTtl: KV_CACHE_TTL_SECONDS }
              );

              if (value === null) {
                return null;
              }

              const metadata =
                item.metadata &&
                typeof item.metadata === "object"
                  ? item.metadata
                  : {};

              const createdAt =
                Number.isFinite(Number(metadata.createdAt))
                  ? Number(metadata.createdAt)
                  : null;

              const metadataExpiry =
                metadata.expiresAt == null
                  ? null
                  : Number(metadata.expiresAt);

              const listedExpiry =
                typeof item.expiration === "number" &&
                Number.isFinite(item.expiration)
                  ? item.expiration * 1000
                  : null;

              const expiresAt =
                Number.isFinite(metadataExpiry)
                  ? metadataExpiry
                  : listedExpiry;

              return {
                name: item.name,
                value,
                createdAt,
                expiresAt,
                hasMetadata: Boolean(
                  metadata && metadata.version
                )
              };
            })
          );


          return json({
            links: links.filter(Boolean),

            cfg: {
              ce: (
                await env.LINKS.get(
                  "SYS_CE",
                  { cacheTtl: KV_CACHE_TTL_SECONDS }
                )
              ) || "false",

              sk: (
                await env.LINKS.get(
                  "SYS_SK",
                  { cacheTtl: KV_CACHE_TTL_SECONDS }
                )
              ) || "",

              secretSource:
                await getTurnstileSecretSource(env)
            },

            rateLimitConfigured: Boolean(
              env.CREATE_LIMITER &&
              typeof env.CREATE_LIMITER.limit === "function"
            ),

            next: list.list_complete
              ? ""
              : (list.cursor || "")
          });
        }


        // ------------------------------------------------------
        // ADMIN SAVE CONFIG
        // ------------------------------------------------------

        if (endpoint === "/admin/api/config") {
          if (request.method !== "POST") {
            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "POST" }
            );
          }

          if (!sameOriginMutation(request)) {
            return json(
              { error: "Cross-origin request rejected" },
              403
            );
          }

          const parsed = await readJsonLimited(
            request,
            4096
          );

          if (!parsed.ok) {
            return json(
              { error: parsed.error },
              parsed.status
            );
          }

          const cfg = parsed.data;

          if (
            !cfg ||
            typeof cfg !== "object" ||
            Array.isArray(cfg)
          ) {
            return json(
              { error: "Invalid configuration" },
              400
            );
          }

          const ce =
            cfg.ce === true || cfg.ce === "true"
              ? "true"
              : "false";

          const sk =
            typeof cfg.sk === "string"
              ? cfg.sk.trim()
              : "";

          if (sk.length > 256) {
            return json(
              { error: "SiteKey 长度不合法" },
              400
            );
          }

          if (ce === "true") {
            if (!sk) {
              return json(
                { error: "开启 Turnstile 前请填写 SiteKey" },
                400
              );
            }

            if (!(await getTurnstileSecret(env))) {
              return json(
                {
                  error: "未检测到 TURNSTILE_SECRET 或旧版 SYS_SS"
                },
                400
              );
            }
          }

          // Keep legacy SYS_SS untouched.
          await env.LINKS.put("SYS_CE", ce);
          await env.LINKS.put("SYS_SK", sk);

          return json({ ok: true });
        }


        // ------------------------------------------------------
        // ADMIN DELETE
        // ------------------------------------------------------

        if (endpoint === "/admin/api/delete") {
          const legacyHeaderAuth =
            request.headers.get("Authorization") === env.ADMIN_PASS;

          let key = "";


          if (request.method === "POST") {
            if (!sameOriginMutation(request)) {
              return json(
                { error: "Cross-origin request rejected" },
                403
              );
            }

            const parsed = await readJsonLimited(
              request,
              4096
            );

            if (!parsed.ok) {
              return json(
                { error: parsed.error },
                parsed.status
              );
            }

            key =
              parsed.data &&
              typeof parsed.data.key === "string"
                ? parsed.data.key
                : "";

          } else if (
            request.method === "GET" &&
            legacyHeaderAuth
          ) {
            // Legacy v2.4 API compatibility.
            key = url.searchParams.get("k") || "";

          } else {
            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "POST" }
            );
          }


          if (!key) {
            return json(
              { error: "No Key" },
              400
            );
          }

          if (
            isSystemKey(key) ||
            HASH_KEY_RE.test(key)
          ) {
            return json(
              { error: "Reserved key" },
              400
            );
          }


          const target = await env.LINKS.get(
            key,
            { cacheTtl: KV_CACHE_TTL_SECONDS }
          );

          if (target === null) {
            return json(
              { error: "短链不存在或已经删除" },
              404
            );
          }


          const tag = await cacheTagForKey(key);

          const localCacheKey =
            cacheKeyRequest(url.origin, key);

          try {
            await caches.default.delete(localCacheKey);
          } catch (error) {
            console.error(
              "Local cache delete failed:",
              error
            );
          }


          await env.LINKS.delete(key);

          await cleanupUrlIndexes(
            env,
            key,
            target
          );


          const tagPurge =
            await purgeGlobalTag(env, tag);

          // Purge the old v2.4 URL cache entry as well.
          const legacyUrlPurge =
            await purgeGlobalLegacyUrl(
              env,
              url.origin,
              key
            );


          const globalPurged =
            tagPurge.global &&
            legacyUrlPurge.global;


          return json({
            ok: true,

            cachePurge: globalPurged
              ? "global"
              : "local-only",

            warning: globalPurged
              ? ""
              : [
                  tagPurge.reason,
                  legacyUrlPurge.reason
                ].filter(Boolean).join("；")
          });
        }


        return json(
          { error: "Not Found" },
          404
        );
      }


      // ========================================================
      // CREATE SHORT URL
      // ========================================================

      if (
        url.pathname === "/api/create" ||
        url.pathname === "/"
      ) {
        if (request.method !== "POST") {
          if (
            request.method === "GET" &&
            url.pathname === "/"
          ) {
            return htmlResponse(INDEX_HTML, true);
          }

          return json(
            { error: "Method Not Allowed" },
            405,
            { Allow: "POST" }
          );
        }


        // Rate limit by client IP.
        const limited = await checkRateLimit(
          env.CREATE_LIMITER,
          "create:" + clientIp(request)
        );

        if (limited.unavailable) {
          return json(
            { error: "创建接口限流服务暂时不可用" },
            503
          );
        }

        if (!limited.allowed) {
          return json(
            { error: "创建过于频繁，请稍后再试" },
            429
          );
        }


        const parsed = await readJsonLimited(request);

        if (!parsed.ok) {
          return json(
            { error: parsed.error },
            parsed.status
          );
        }

        const data = parsed.data;

        if (
          !data ||
          typeof data !== "object" ||
          Array.isArray(data)
        ) {
          return json(
            { error: "Invalid Payload" },
            400
          );
        }


        const legacyTarget = legacyFixURL(data.url);

        const targetUrl = fixURL(data.url);

        if (!targetUrl || !legacyTarget) {
          return json(
            { error: "Invalid URL" },
            400
          );
        }


        if (
          data.key != null &&
          typeof data.key !== "string"
        ) {
          return json(
            { error: "Invalid key" },
            400
          );
        }

        const customKey =
          typeof data.key === "string"
            ? data.key.trim()
            : "";

        if (
          customKey &&
          !isValidNewKey(customKey)
        ) {
          return json(
            {
              error: "自定义后缀仅允许 1-40 位字母、数字、下划线或连字符，且不能使用系统保留名称"
            },
            400
          );
        }


        const expire =
          data.expire == null || data.expire === ""
            ? 0
            : Number(data.expire);

        if (
          !Number.isInteger(expire) ||
          !ALLOWED_EXPIRATIONS.has(expire)
        ) {
          return json(
            {
              error: "有效期仅支持永久、1 天或 30 天"
            },
            400
          );
        }


        // Optional Turnstile.
        const captchaEnabled =
          (await env.LINKS.get(
            "SYS_CE",
            { cacheTtl: KV_CACHE_TTL_SECONDS }
          )) === "true";

        if (captchaEnabled) {
          const verification = await verifyTurnstile(
            request,
            env,
            data.token
          );

          if (!verification.ok) {
            return json(
              { error: verification.error },
              verification.status
            );
          }
        }


        // Preserve old v2.4 and v2.5 SHA256 index formats.
        const hashCandidates = [
          ...new Set([
            await sha256(legacyTarget),
            await sha256(targetUrl)
          ])
        ];


        let key = customKey;

        const now = Date.now();

        const expiresAt =
          expire > 0
            ? now + expire * 1000
            : null;


        const metadata = {
          version: VERSION,
          createdAt: now,
          expiresAt
        };


        const putOptions =
          expire > 0
            ? {
                expirationTtl: expire,
                metadata
              }
            : {
                metadata
              };


        // ------------------------------------------------------
        // AUTOMATIC KEY + OLD HASH INDEX COMPATIBILITY
        // ------------------------------------------------------

        if (!customKey) {
          for (const hash of hashCandidates) {
            const mapped = await env.LINKS.get(
              hash,
              { cacheTtl: KV_CACHE_TTL_SECONDS }
            );

            if (
              !mapped ||
              typeof mapped !== "string"
            ) {
              continue;
            }

            const oldTarget = await env.LINKS.get(
              mapped,
              { cacheTtl: KV_CACHE_TTL_SECONDS }
            );

            if (oldTarget !== null) {
              const oldCanonical = fixURL(oldTarget);

              if (
                oldCanonical === targetUrl ||
                oldTarget === legacyTarget
              ) {
                return json({
                  key: "/" + mapped,
                  reused: true
                });
              }

            } else {
              await env.LINKS.delete(hash);
            }
          }


          // Generate a cryptographically secure random key.
          let allocated = false;

          for (let attempt = 0; attempt < 16; attempt++) {
            const candidate = randomShortKey(10);

            const exists = await env.LINKS.get(
              candidate,
              { cacheTtl: KV_CACHE_TTL_SECONDS }
            );

            if (exists === null) {
              key = candidate;
              allocated = true;
              break;
            }
          }

          if (!allocated) {
            return json(
              { error: "暂时无法分配短码，请重试" },
              503
            );
          }

        } else {
          // Custom key preflight.
          const existing = await env.LINKS.get(
            key,
            { cacheTtl: KV_CACHE_TTL_SECONDS }
          );

          if (existing !== null) {
            return json(
              { error: "Key Exists" },
              409
            );
          }
        }


        // KV has no atomic create-if-absent operation.
        // Preflight checks reduce accidental collisions but cannot
        // eliminate simultaneous write races.
        await env.LINKS.put(
          key,
          targetUrl,
          putOptions
        );


        // Only auto-generated links receive SHA256 indexes.
        if (!customKey) {
          try {
            await Promise.all(
              hashCandidates.map(hash =>
                env.LINKS.put(
                  hash,
                  key,
                  expire > 0
                    ? { expirationTtl: expire }
                    : undefined
                )
              )
            );

          } catch (error) {
            await env.LINKS.delete(key);

            for (const hash of hashCandidates) {
              await env.LINKS.delete(hash).catch(() => {});
            }

            throw error;
          }
        }


        return json({
          key: "/" + key,
          reused: false
        });
      }


      // ========================================================
      // SHORT URL REDIRECT WITH 24-HOUR EDGE CACHE
      // ========================================================

      if (
        request.method === "GET" &&
        path &&
        ![
          "admin",
          "api",
          "favicon.ico"
        ].includes(path)
      ) {
        if (path.length > 512) {
          return textResponse(
            "404 Not Found",
            404
          );
        }


        const cacheKey = cacheKeyRequest(
          url.origin,
          path
        );


        // ------------------------------------------------------
        // CACHE HIT
        // ------------------------------------------------------

        let cached;

        try {
          cached = await caches.default.match(cacheKey);

        } catch (error) {
          console.error(
            "Cache match failed:",
            error
          );
        }


        if (cached) {
          const location =
            cached.headers.get("Location");

          if (location && fixURL(location)) {
            return clientRedirectResponse(
              location,
              "HIT"
            );
          }
        }


        // ------------------------------------------------------
        // CACHE MISS: READ KV
        // ------------------------------------------------------

        const record = await env.LINKS.getWithMetadata(
          path,
          { cacheTtl: KV_CACHE_TTL_SECONDS }
        );

        const targetValue = record && record.value;

        if (
          targetValue === null ||
          targetValue === undefined
        ) {
          return textResponse(
            "404 Not Found",
            404
          );
        }


        const safeTarget = fixURL(targetValue);

        if (!safeTarget) {
          console.error(
            "Blocked invalid legacy redirect target for key:",
            path
          );

          return textResponse(
            "404 Not Found",
            404
          );
        }


        // ------------------------------------------------------
        // DETERMINE EXPIRATION
        //
        // v2.6 records use metadata.
        // v2.4/v2.5 records use KV list() to inspect the exact
        // key's expiration so the cache does not outlive the link.
        // ------------------------------------------------------

        const metadata =
          record.metadata &&
          typeof record.metadata === "object"
            ? record.metadata
            : null;

        const hasV26Metadata =
          metadata &&
          metadata.version === VERSION &&
          Object.prototype.hasOwnProperty.call(
            metadata,
            "expiresAt"
          );


        let expiresAt = null;

        let expiryKnown = Boolean(hasV26Metadata);


        if (hasV26Metadata) {
          expiresAt =
            metadata.expiresAt == null
              ? null
              : Number(metadata.expiresAt);

        } else {
          // Legacy records: query exact key metadata.
          // This extra list operation happens only on cache MISS.
          try {
            const keyList = await env.LINKS.list({
              prefix: path,
              limit: 1
            });

            const exactKey = keyList.keys.find(
              item => item.name === path
            );

            if (exactKey) {
              expiryKnown = true;

              expiresAt =
                typeof exactKey.expiration === "number" &&
                Number.isFinite(exactKey.expiration)
                  ? exactKey.expiration * 1000
                  : null;
            }

          } catch (error) {
            console.error(
              "Legacy KV expiry lookup failed; bypassing cache:",
              error
            );
          }
        }


        // ------------------------------------------------------
        // CACHE TTL
        // ------------------------------------------------------

        if (expiryKnown) {
          if (
            expiresAt !== null &&
            (
              !Number.isFinite(expiresAt) ||
              expiresAt <= Date.now()
            )
          ) {
            return textResponse(
              "404 Not Found",
              404
            );
          }


          let ttl = CACHE_TTL_SECONDS;

          if (expiresAt !== null) {
            ttl = Math.min(
              CACHE_TTL_SECONDS,
              Math.floor(
                (expiresAt - Date.now()) / 1000
              )
            );
          }


          if (ttl > 0) {
            const tag = await cacheTagForKey(path);

            const cachedResponse = new Response(
              null,
              {
                status: 302,
                headers: {
                  Location: safeTarget,
                  "Cache-Control": `public, max-age=${ttl}`,
                  "Cache-Tag": tag
                }
              }
            );


            // Store in this Cloudflare data center's Cache API.
            ctx.waitUntil(
              caches.default.put(
                cacheKey,
                cachedResponse
              ).catch(error => {
                console.error(
                  "Cache put failed:",
                  error
                );
              })
            );


            return clientRedirectResponse(
              safeTarget,
              "MISS"
            );
          }
        }


        // Do not cache if expiry could not be confirmed.
        return clientRedirectResponse(
          safeTarget,
          "BYPASS-LEGACY"
        );
      }


      // ========================================================
      // MAIN PAGE
      // ========================================================

      if (
        request.method === "GET" &&
        url.pathname === "/"
      ) {
        return htmlResponse(
          INDEX_HTML,
          true
        );
      }


      if (
        request.method !== "GET" &&
        request.method !== "HEAD"
      ) {
        return textResponse(
          "Method Not Allowed",
          405
        );
      }


      return textResponse(
        "404 Not Found",
        404
      );


    } catch (error) {
      console.error(
        "Short URL Worker error:",
        error
      );

      return json(
        { error: "Internal Server Error" },
        500
      );
    }
  }
};
