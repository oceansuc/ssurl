// Cloudflare Worker Short URL v2.5
// KV binding: LINKS
// Required Worker Secret: ADMIN_PASS
// Recommended Worker Secret: TURNSTILE_SECRET
// Backward compatibility: if TURNSTILE_SECRET is not configured, the Worker
// temporarily falls back to the legacy LINKS KV value SYS_SS. The legacy value
// is never returned to the browser.

const HASH_KEY_RE = /^[a-f0-9]{64}$/i;

const RESERVED_KEYS = new Set([
  "admin",
  "api",
  "favicon.ico"
]);

const SHORT_KEY_RE = /^[A-Za-z0-9_-]{1,40}$/;

const RANDOM_ALPHABET =
  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store, max-age=0",
      ...extraHeaders
    }
  });
}

function isSystemKey(key) {
  return typeof key === "string" && /^SYS_/i.test(key);
}

// New short codes may only use URL-safe characters and may not overlap with
// reserved routes, system settings, or the existing SHA-256 de-duplication keys.
// Existing historical KV keys are not rewritten, so old links remain readable.
function isValidNewKey(key) {
  if (typeof key !== "string" || !SHORT_KEY_RE.test(key)) {
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

// URL validation
function fixURL(input) {
  if (typeof input !== "string") {
    return null;
  }

  let value = input.trim();

  if (!value || value.length > 2048) {
    return null;
  }

  if (!/^https?:\/\//i.test(value)) {
    value = "https://" + value;
  }

  try {
    const parsed = new URL(value);

    if (
      parsed.protocol !== "http:" &&
      parsed.protocol !== "https:"
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

    return parsed.href;

  } catch {
    return null;
  }
}

// SHA-256
async function sha256(value) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(
    new Uint8Array(bytes),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}

// Cryptographically secure random key generation.
// Rejection sampling avoids modulo bias.
// KV still does not provide atomic create-if-absent writes.
function randomShortKey(length = 9) {
  let result = "";

  const limit =
    Math.floor(256 / RANDOM_ALPHABET.length) *
    RANDOM_ALPHABET.length;

  const bytes = new Uint8Array(Math.max(16, length * 2));

  while (result.length < length) {
    crypto.getRandomValues(bytes);

    for (const byte of bytes) {
      if (byte >= limit) {
        continue;
      }

      result += RANDOM_ALPHABET[
        byte % RANDOM_ALPHABET.length
      ];

      if (result.length === length) {
        break;
      }
    }
  }

  return result;
}

// Turnstile Secret compatibility
async function getTurnstileSecret(env) {
  // Prefer dedicated Worker Secret.
  const dedicated =
    typeof env.TURNSTILE_SECRET === "string"
      ? env.TURNSTILE_SECRET.trim()
      : "";

  if (dedicated) {
    return dedicated;
  }

  // Legacy compatibility: old KV SYS_SS.
  return (await env.LINKS.get("SYS_SS")) || "";
}

async function hasTurnstileSecret(env) {
  return Boolean(await getTurnstileSecret(env));
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
    (await env.LINKS.get("SYS_SS")) || "";

  return legacy ? "legacy" : "missing";
}

// Turnstile verification
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

  // Remote IP is optional.
  const remoteIp =
    request.headers.get("CF-Connecting-IP");

  if (remoteIp) {
    form.append("remoteip", remoteIp);
  }

  let verifyResponse;
  let result;

  try {
    verifyResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body: form
      }
    );

    if (!verifyResponse.ok) {
      return {
        ok: false,
        status: 502,
        error: "验证码服务暂时不可用"
      };
    }

    result = await verifyResponse.json();

  } catch (error) {
    console.error(
      "Turnstile verification request failed:",
      error
    );

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

  // Validate hostname when Cloudflare includes it.
  // Compatible with legacy tokens without an action value.
  if (result.hostname) {
    const requestHost =
      new URL(request.url).hostname.toLowerCase();

    if (
      String(result.hostname).toLowerCase() !==
      requestHost
    ) {
      return {
        ok: false,
        status: 403,
        error: "验证码域名不匹配"
      };
    }
  }

  return { ok: true };
}


// ============================================================
// ADMIN HTML
// ============================================================

const ADMIN_HTML = `<!doctype html>
<html lang="zh-CN">

<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>短链接管理后台</title>

<style>

body{
  font-family:Arial,sans-serif;
  background:#f5f7fa;
  padding:20px;
  margin:0;
  display:flex;
  justify-content:center
}

.container{
  width:100%;
  max-width:900px
}

.card{
  background:white;
  padding:24px;
  border-radius:10px;
  box-shadow:0 2px 8px rgba(0,0,0,.05);
  margin-bottom:20px
}

.login-box{
  max-width:320px;
  margin:80px auto;
  text-align:center
}

.header{
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  margin-bottom:20px;
  border-bottom:1px solid #eee;
  padding-bottom:12px
}

h2,h3{
  margin:0 0 12px
}

table{
  width:100%;
  border-collapse:collapse;
  margin-top:10px
}

td,th{
  padding:10px;
  border-bottom:1px solid #ddd;
  word-break:break-all;
  text-align:left
}

th{
  background:#f9fafb
}

input[type=text],
input[type=password]{
  width:100%;
  padding:8px;
  margin:6px 0 12px;
  box-sizing:border-box;
  border:1px solid #ccc;
  border-radius:6px
}

button{
  cursor:pointer;
  padding:8px 16px;
  border-radius:6px;
  border:1px solid #ccc;
  background:#fff;
  font-weight:bold
}

button.primary{
  background:#2563eb;
  color:#fff;
  border:none
}

button.danger{
  background:#ef4444;
  color:#fff;
  border:none
}

button:disabled{
  opacity:.55;
  cursor:not-allowed
}

.err{
  color:#dc2626;
  font-size:14px;
  margin-top:8px;
  white-space:pre-wrap
}

.note{
  font-size:13px;
  color:#64748b;
  line-height:1.6
}

.status{
  font-size:14px;
  margin:10px 0;
  color:#334155
}

@media(max-width:600px){

  body{
    padding:10px
  }

  .card{
    padding:16px
  }

  .header{
    align-items:flex-start;
    flex-direction:column
  }

  td,th{
    padding:7px;
    font-size:13px
  }

}

</style>
</head>

<body>

<div class="container">

  <div id="login-box"
       class="card login-box"
       style="display:none">

    <h2>管理员登录</h2>

    <input
      id="pass-input"
      type="password"
      placeholder="请输入管理员密码"
      autocomplete="current-password"
    >

    <button id="login-btn" class="primary">
      登 录
    </button>

    <div
      id="login-err"
      class="err"
      style="display:none"
    >
      密码错误
    </div>

  </div>


  <div id="admin-app"
       class="card"
       style="display:none">

    <div class="header">

      <h2>短链接管理后台</h2>

      <button id="logout-btn" class="danger">
        退出登录
      </button>

    </div>


    <section style="margin-bottom:20px">

      <h3>安全与验证码设置</h3>

      <label>
        <input id="ce" type="checkbox">
        开启 Turnstile 验证码
      </label>

      <br><br>

      SiteKey:
      <br>

      <input
        id="sk"
        type="text"
        style="max-width:400px"
        autocomplete="off"
      >

      <div id="secret-status" class="status"></div>

      <p class="note">
        Turnstile Secret 不再从 KV 发送到浏览器，也不会在此页面显示。
        请在 Cloudflare Worker 的 Settings → Variables and Secrets
        中添加 Secret，名称为 TURNSTILE_SECRET。
        旧版 KV 中的 SYS_SS 暂时保留为兼容后备值。
      </p>

      <button id="save-config-btn" class="primary">
        保存配置
      </button>

      <div id="config-msg" class="err"></div>

    </section>


    <hr style="border:none;border-top:1px solid #eee;margin:20px 0">

    <h3>链接列表</h3>

    <div id="list-container" class="status">
      加载中...
    </div>

  </div>

</div>


<script>

function getPass(){
  return localStorage.getItem("ADMIN_PASS") || "";
}

function showLogin(errText){

  document.getElementById("admin-app").style.display = "none";

  document.getElementById("login-box").style.display = "block";

  const errorNode =
    document.getElementById("login-err");

  if(errText){

    errorNode.textContent = errText;
    errorNode.style.display = "block";

  }else{

    errorNode.textContent = "";
    errorNode.style.display = "none";

  }

}

function logout(){

  localStorage.removeItem("ADMIN_PASS");

  document.getElementById("pass-input").value = "";

  showLogin();

}

async function doLogin(){

  const password =
    document.getElementById("pass-input").value;

  if(!password) return;

  localStorage.setItem("ADMIN_PASS", password);

  await loadData();

}

function showListError(message){

  const container =
    document.getElementById("list-container");

  container.replaceChildren();

  const errorNode =
    document.createElement("div");

  errorNode.className = "err";

  errorNode.textContent = message;

  container.appendChild(errorNode);

}


// Safe DOM rendering.
// Never put untrusted KV values into innerHTML.
function renderLinks(data){

  const container =
    document.getElementById("list-container");

  container.replaceChildren();

  const table =
    document.createElement("table");

  const head =
    document.createElement("thead");

  const headRow =
    document.createElement("tr");

  ["Key", "原 URL", "操作"].forEach(function(label){

    const th = document.createElement("th");

    th.textContent = label;

    headRow.appendChild(th);

  });

  head.appendChild(headRow);

  table.appendChild(head);


  const body =
    document.createElement("tbody");

  (Array.isArray(data.links) ? data.links : [])
    .forEach(function(item){

      const row =
        document.createElement("tr");


      const keyCell =
        document.createElement("td");

      keyCell.textContent =
        String(item.name == null ? "" : item.name);

      row.appendChild(keyCell);


      const urlCell =
        document.createElement("td");

      urlCell.textContent =
        String(item.value == null ? "" : item.value);

      row.appendChild(urlCell);


      const actionCell =
        document.createElement("td");

      const deleteButton =
        document.createElement("button");

      deleteButton.className = "danger del-btn";

      deleteButton.textContent = "删除";

      // Dataset assignment does not parse HTML.
      deleteButton.dataset.key =
        String(item.name == null ? "" : item.name);

      actionCell.appendChild(deleteButton);

      row.appendChild(actionCell);

      body.appendChild(row);

    });


  table.appendChild(body);

  container.appendChild(table);


  if(data.next){

    const nextButton =
      document.createElement("button");

    nextButton.id = "next-btn";

    nextButton.textContent = "下一页";

    nextButton.style.marginTop = "12px";

    nextButton.dataset.next = String(data.next);

    container.appendChild(nextButton);

  }


  if(!data.links || data.links.length === 0){

    const empty =
      document.createElement("p");

    empty.className = "note";

    empty.textContent = "当前页没有短链记录。";

    container.appendChild(empty);

  }

}


async function loadData(cursor){

  const pass = getPass();

  if(!pass){

    showLogin();

    return;

  }

  const container =
    document.getElementById("list-container");

  container.textContent = "加载中...";

  try{

    const query =
      cursor
        ? "?cursor=" + encodeURIComponent(cursor)
        : "";

    const response = await fetch(
      "/admin/api/all" + query,
      {
        method: "GET",
        cache: "no-store",
        headers: {
          Authorization: pass
        }
      }
    );


    if(response.status === 401){

      localStorage.removeItem("ADMIN_PASS");

      showLogin("密码错误");

      return;

    }

    if(!response.ok){

      throw new Error("HTTP " + response.status);

    }

    const data = await response.json();

    document.getElementById("login-box").style.display = "none";

    document.getElementById("admin-app").style.display = "block";


    document.getElementById("ce").checked =
      data.cfg && data.cfg.ce === "true";


    document.getElementById("sk").value =
      data.cfg && data.cfg.sk
        ? data.cfg.sk
        : "";


    const secretSource =
      data.cfg
        ? data.cfg.secretSource
        : "missing";


    document.getElementById("secret-status").textContent =
      secretSource === "worker"
        ? "Turnstile Secret：已配置为 Worker Secret（不会发送到浏览器）"
        : secretSource === "legacy"
          ? "Turnstile Secret：目前使用旧 KV 后备值 SYS_SS；建议迁移到 Worker Secret TURNSTILE_SECRET。"
          : "Turnstile Secret：未配置；如开启验证码，需先添加 TURNSTILE_SECRET。";


    renderLinks(data);

  }catch(error){

    showListError(
      "加载失败：" +
      String(error && error.message ? error.message : error)
    );

  }

}


async function deleteLink(key){

  if(!key) return;

  if(!confirm("确定删除短链接：" + key + "？")) {
    return;
  }

  try{

    const response = await fetch(
      "/admin/api/delete?k=" + encodeURIComponent(key),
      {
        method: "GET",
        cache: "no-store",
        headers: {
          Authorization: getPass()
        }
      }
    );


    if(response.status === 401){

      localStorage.removeItem("ADMIN_PASS");

      showLogin("密码错误");

      return;

    }


    if(!response.ok){

      const message = await response.text();

      throw new Error(
        message || ("HTTP " + response.status)
      );

    }

    await loadData();

  }catch(error){

    alert(
      "删除失败：" +
      String(error && error.message ? error.message : error)
    );

  }

}


async function saveConfig(){

  const messageNode =
    document.getElementById("config-msg");

  messageNode.textContent = "正在保存...";

  try{

    const response = await fetch(
      "/admin/api/config",
      {
        method: "POST",
        cache: "no-store",

        headers: {
          Authorization: getPass(),
          "Content-Type": "application/json"
        },

        body: JSON.stringify({

          ce: document.getElementById("ce").checked,

          sk: document.getElementById("sk").value.trim()

        })

      }
    );


    if(response.status === 401){

      localStorage.removeItem("ADMIN_PASS");

      showLogin("密码错误");

      return;

    }


    const result = await response.json().catch(
      function(){
        return {};
      }
    );


    if(!response.ok){

      throw new Error(
        result.error || ("HTTP " + response.status)
      );

    }


    messageNode.textContent = "配置保存成功。";

    await loadData();

  }catch(error){

    messageNode.textContent =
      "保存失败：" +
      String(error && error.message ? error.message : error);

  }

}


document.getElementById("login-btn")
  .addEventListener("click", doLogin);


document.getElementById("pass-input")
  .addEventListener("keydown", function(event){

    if(event.key === "Enter") {
      doLogin();
    }

  });


document.getElementById("logout-btn")
  .addEventListener("click", logout);


document.getElementById("save-config-btn")
  .addEventListener("click", saveConfig);


document.getElementById("list-container")
  .addEventListener("click", function(event){

    const target = event.target;

    if(!(target instanceof Element)) {
      return;
    }


    const deleteButton =
      target.closest(".del-btn");

    if(deleteButton){

      deleteLink(deleteButton.dataset.key || "");

      return;

    }


    const nextButton =
      target.closest("#next-btn");

    if(nextButton){

      loadData(nextButton.dataset.next || "");

    }

  });


loadData();

</script>
</body>
</html>`;


// ============================================================
// FRONTEND HTML
// ============================================================

const INDEX_HTML = `<!doctype html>
<html lang="zh-CN">

<head>

<meta charset="utf-8">

<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Short URL</title>

<style>

body{
  font-family:Arial,sans-serif;
  display:flex;
  justify-content:center;
  align-items:center;
  min-height:100vh;
  background:#f5f7fa;
  margin:0;
  padding:16px;
  box-sizing:border-box
}

.box{
  background:white;
  padding:30px;
  border-radius:12px;
  width:330px;
  max-width:100%;
  box-shadow:0 4px 12px rgba(0,0,0,.1);
  box-sizing:border-box
}

input,button,select{
  width:100%;
  padding:10px;
  margin:5px 0;
  box-sizing:border-box
}

button{
  background:#2563eb;
  color:white;
  border:0;
  border-radius:5px;
  cursor:pointer;
  font-weight:bold
}

button:hover{
  background:#1d4ed8
}

button:disabled{
  opacity:.55;
  cursor:not-allowed
}

#r{
  word-break:break-all;
  color:#2563eb;
  font-weight:bold
}

.note{
  font-size:12px;
  color:#64748b
}

</style>

</head>


<body>

<div class="box">

  <h3>短链接生成</h3>

  <input
    id="u"
    type="text"
    placeholder="例如 www.baidu.com 或 https://..."
    autocomplete="url"
  >

  <input
    id="k"
    type="text"
    placeholder="自定义后缀（可选）"
    autocomplete="off"
  >

  <select id="e">

    <option value="0">永久有效</option>

    <option value="86400">1天</option>

    <option value="2592000">30天</option>

  </select>

  <div id="tc"></div>

  <p id="captcha-note" class="note"></p>

  <button id="b" type="button">
    生成短链
  </button>

  <p id="r"></p>

  <button id="copy-btn" type="button">
    复制链接
  </button>

</div>


<script>

let token = "";

let captchaEnabled = false;

let widgetId = null;

const createButton =
  document.getElementById("b");

const resultNode =
  document.getElementById("r");


// Initialize UI configuration and Turnstile.
async function init(){

  try{

    const response = await fetch(
      "/api/ui-cfg",
      {
        cache: "no-store"
      }
    );

    if(!response.ok){

      throw new Error("HTTP " + response.status);

    }

    const config = await response.json();

    captchaEnabled = config.ce === "true";


    if(!captchaEnabled){

      return;

    }


    createButton.disabled = true;


    if(!config.sk){

      document.getElementById("captcha-note").textContent =
        "验证码配置不完整，请联系管理员。";

      return;

    }


    const script =
      document.createElement("script");

    script.src =
      "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

    script.async = true;

    script.defer = true;


    script.onload = function(){

      if(!window.turnstile){

        document.getElementById("captcha-note").textContent =
          "验证码加载失败，请刷新页面。";

        return;

      }


      widgetId = window.turnstile.render(
        document.getElementById("tc"),
        {

          sitekey: config.sk,

          callback: function(value){

            token = value;

            createButton.disabled = false;

            document.getElementById("captcha-note").textContent = "";

          },


          "expired-callback": function(){

            token = "";

            createButton.disabled = true;

            document.getElementById("captcha-note").textContent =
              "验证码已过期，请重新验证。";

          },


          "error-callback": function(){

            token = "";

            createButton.disabled = true;

            document.getElementById("captcha-note").textContent =
              "验证码加载或验证失败，请刷新页面重试。";

          }

        }
      );

    };


    script.onerror = function(){

      document.getElementById("captcha-note").textContent =
        "验证码加载失败，请检查网络后刷新页面。";

    };


    document.head.appendChild(script);


  }catch(error){

    // Backend remains authoritative.
    console.error("UI config load failed:", error);

  }

}


// Create short URL.
async function create(){

  const rawUrl =
    document.getElementById("u").value.trim();

  const customKey =
    document.getElementById("k").value.trim();


  if(!rawUrl){

    alert("请输入链接");

    return;

  }


  if(captchaEnabled && !token){

    alert("请先完成验证码");

    return;

  }


  createButton.disabled = true;

  resultNode.textContent = "正在生成...";


  try{

    const response = await fetch(
      "/api/create",
      {

        method: "POST",

        headers: {
          "Content-Type": "application/json"
        },

        body: JSON.stringify({

          url: rawUrl,

          key: customKey,

          expire: document.getElementById("e").value,

          token: token

        })

      }
    );


    const data = await response.json().catch(
      function(){
        return {};
      }
    );


    if(!response.ok || !data.key){

      resultNode.textContent = "";

      alert(
        data.error ||
        "生成失败（HTTP " + response.status + "）"
      );

      return;

    }


    resultNode.textContent =
      location.origin + data.key;


  }catch(error){

    resultNode.textContent = "";

    alert("网络请求失败，请重试");


  }finally{

    if(
      captchaEnabled &&
      widgetId !== null &&
      window.turnstile
    ){

      token = "";

      window.turnstile.reset(widgetId);

      createButton.disabled = true;

    }else{

      createButton.disabled = false;

    }

  }

}


// Copy short URL.
async function copyResult(){

  const value = resultNode.textContent;

  if(!value || value === "正在生成...") {
    return;
  }

  try{

    await navigator.clipboard.writeText(value);

    alert("已复制到剪贴板！");

  }catch(error){

    alert("复制失败，请手动复制短链接。");

  }

}


createButton.addEventListener("click", create);

document.getElementById("copy-btn")
  .addEventListener("click", copyResult);


init();

</script>

</body>
</html>`;
// ============================================================
// CLOUDFLARE WORKER
// ============================================================

export default {

  async fetch(request, env) {

    const requestUrl = new URL(request.url);

    let path;

    try {

      path = decodeURIComponent(
        requestUrl.pathname.slice(1)
      );

    } catch {

      return new Response("Bad Request", {
        status: 400
      });

    }


    const auth =
      request.headers.get("Authorization");


    try {

      // ========================================================
      // ADMIN PAGE
      // ========================================================

      if (requestUrl.pathname === "/admin") {

        if (
          request.method !== "GET" &&
          request.method !== "HEAD"
        ) {

          return new Response("Method Not Allowed", {
            status: 405
          });

        }


        return new Response(ADMIN_HTML, {

          headers: {

            "Content-Type": "text/html; charset=UTF-8",

            "Cache-Control": "no-store, max-age=0"

          }

        });

      }


      // ========================================================
      // PUBLIC UI CONFIG
      // SiteKey is public. Secret is NEVER returned.
      // ========================================================

      if (requestUrl.pathname === "/api/ui-cfg") {

        if (request.method !== "GET") {

          return json(
            { error: "Method Not Allowed" },
            405,
            { Allow: "GET" }
          );

        }


        return json({

          ce: (await env.LINKS.get("SYS_CE")) || "false",

          sk: (await env.LINKS.get("SYS_SK")) || ""

        });

      }


      // ========================================================
      // ADMIN APIs
      // Retain v2.4 Authorization header format.
      // ========================================================

      if (requestUrl.pathname.startsWith("/admin/api/")) {

        if (
          !env.ADMIN_PASS ||
          !auth ||
          auth !== env.ADMIN_PASS
        ) {

          return new Response("Unauthorized", {

            status: 401,

            headers: {
              "Cache-Control": "no-store, max-age=0"
            }

          });

        }


        // ------------------------------------------------------
        // ADMIN: LIST LINKS
        // ------------------------------------------------------

        if (requestUrl.pathname === "/admin/api/all") {

          if (request.method !== "GET") {

            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "GET" }
            );

          }


          const cursor =
            requestUrl.searchParams.get("cursor") ||
            undefined;


          const list = await env.LINKS.list({

            limit: 20,

            cursor

          });


          // Hide system records and SHA-256 indexes.
          // Historical short links remain visible.
          const visibleKeys = list.keys.filter(item =>

            !isSystemKey(item.name) &&

            !HASH_KEY_RE.test(item.name) &&

            item.name.length < 60

          );


          const links = await Promise.all(

            visibleKeys.map(async item => ({

              name: item.name,

              value: await env.LINKS.get(item.name)

            }))

          );


          return json({

            links,

            cfg: {

              ce: (await env.LINKS.get("SYS_CE")) || "false",

              sk: (await env.LINKS.get("SYS_SK")) || "",

              secretSource: await getTurnstileSecretSource(env)

            },

            next: list.list_complete
              ? ""
              : (list.cursor || "")

          });

        }


        // ------------------------------------------------------
        // ADMIN: SAVE CONFIG
        // Do not expose or overwrite legacy SYS_SS.
        // ------------------------------------------------------

        if (requestUrl.pathname === "/admin/api/config") {

          if (request.method !== "POST") {

            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "POST" }
            );

          }


          let config;

          try {

            config = await request.json();

          } catch {

            return json(
              { error: "Invalid JSON" },
              400
            );

          }


          if (
            !config ||
            typeof config !== "object" ||
            Array.isArray(config)
          ) {

            return json(
              { error: "Invalid configuration" },
              400
            );

          }


          const ce =
            config.ce === true ||
            config.ce === "true"
              ? "true"
              : "false";


          const sk =
            typeof config.sk === "string"
              ? config.sk.trim()
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


            if (!(await hasTurnstileSecret(env))) {

              return json({

                error:
                  "未检测到 Turnstile Secret。请先在 Worker Secrets 中配置 TURNSTILE_SECRET。"

              }, 400);

            }

          }


          // Keep legacy SYS_SS untouched.
          // Dedicated Worker Secret takes priority.
          await env.LINKS.put("SYS_CE", ce);

          await env.LINKS.put("SYS_SK", sk);


          return json({
            ok: true
          });

        }


        // ------------------------------------------------------
        // ADMIN: DELETE LINK
        // Keep GET endpoint for v2.4 compatibility.
        // ------------------------------------------------------

        if (requestUrl.pathname === "/admin/api/delete") {

          if (request.method !== "GET") {

            return json(
              { error: "Method Not Allowed" },
              405,
              { Allow: "GET" }
            );

          }


          const key =
            requestUrl.searchParams.get("k");


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


          // Read existing target.
          const value = await env.LINKS.get(
            key,
            { cacheTtl: 30 }
          );


          if (value !== null) {

            const hash = await sha256(value);

            const mappedKey = await env.LINKS.get(
              hash,
              { cacheTtl: 30 }
            );


            // Delete only the matching de-duplication index.
            if (mappedKey === key) {

              await env.LINKS.delete(hash);

            }

          }


          // Delete short link.
          await env.LINKS.delete(key);


          // No Cache API deletion is required.
          // v2.5 no longer reads or writes redirect cache entries.
          return json({
            ok: true
          });

        }


        return json(
          { error: "Not Found" },
          404
        );

      }


      // ========================================================
      // CREATE SHORT URL
      // Compatible with:
      // POST /api/create
      // POST /
      // ========================================================

      if (
        request.method === "POST" &&
        (
          requestUrl.pathname === "/api/create" ||
          requestUrl.pathname === "/"
        )
      ) {

        // Request size limit.
        const contentLength = Number(
          request.headers.get("Content-Length") || 0
        );


        if (contentLength > 8192) {

          return json(
            { error: "Payload Too Large" },
            413
          );

        }


        // Parse JSON.
        let data;

        try {

          data = await request.json();

        } catch {

          return json(
            { error: "Invalid Payload" },
            400
          );

        }


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


        // Validate target URL.
        const targetUrl = fixURL(data.url);


        if (!targetUrl) {

          return json(
            { error: "Invalid URL" },
            400
          );

        }


        // Validate expiration.
        const expire = Number(data.expire);

        const allowedExpirations = [
          0,
          86400,
          2592000
        ];


        if (
          !Number.isInteger(expire) ||
          !allowedExpirations.includes(expire)
        ) {

          return json(
            { error: "Invalid expiration" },
            400
          );

        }


        // Validate custom key type.
        const customKey =
          typeof data.key === "string"
            ? data.key.trim()
            : "";


        if (
          data.key != null &&
          typeof data.key !== "string"
        ) {

          return json(
            { error: "Invalid key" },
            400
          );

        }


        // Validate custom key and system namespace.
        if (
          customKey &&
          !isValidNewKey(customKey)
        ) {

          return json({

            error:
              "自定义后缀仅允许 1-40 位字母、数字、下划线或连字符，且不能使用系统保留名称"

          }, 400);

        }


        // ------------------------------------------------------
        // TURNSTILE
        // ------------------------------------------------------

        const captchaEnabled =
          (await env.LINKS.get("SYS_CE")) === "true";


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


        // ------------------------------------------------------
        // SHA-256 DEDUPLICATION
        // Preserve existing v2.4 KV structure:
        //
        // SHA256(URL) -> short code
        // short code -> original URL
        // ------------------------------------------------------

        const hash = await sha256(targetUrl);


        const putOptions =
          expire > 0
            ? { expirationTtl: expire }
            : undefined;


        let key = customKey;


        // ------------------------------------------------------
        // AUTOMATIC SHORT CODE
        // ------------------------------------------------------

        if (!customKey) {

          // Check historical deduplication index.
          const oldKey = await env.LINKS.get(
            hash,
            { cacheTtl: 30 }
          );


          if (oldKey) {

            const oldTarget = await env.LINKS.get(
              oldKey,
              { cacheTtl: 30 }
            );


            if (oldTarget !== null) {

              // Reuse the existing short link.
              return json({
                key: "/" + oldKey
              });

            }


            // Remove orphaned index.
            await env.LINKS.delete(hash);

          }


          // Generate a cryptographically secure random short code.
          // Check that the generated key does not already exist.
          let foundFreeKey = false;


          for (let attempt = 0; attempt < 12; attempt++) {

            const candidate = randomShortKey(9);


            const existing = await env.LINKS.get(
              candidate,
              { cacheTtl: 30 }
            );


            if (existing === null) {

              key = candidate;

              foundFreeKey = true;

              break;

            }

          }


          if (!foundFreeKey) {

            return json({

              error: "暂时无法分配短码，请重试"

            }, 503);

          }

        }


        // ------------------------------------------------------
        // CUSTOM SHORT CODE
        // ------------------------------------------------------

        else {

          // KV has no atomic create-if-absent operation.
          // This check prevents ordinary accidental overwrite.
          // Concurrent requests can still race.
          const existing = await env.LINKS.get(
            key,
            { cacheTtl: 30 }
          );


          if (existing !== null) {

            return json(
              { error: "Key Exists" },
              409
            );

          }

        }


        // ------------------------------------------------------
        // SAVE LINK
        // ------------------------------------------------------

        await env.LINKS.put(
          key,
          targetUrl,
          putOptions
        );


        // Only automatic short codes create a hash index.
        if (!customKey) {

          await env.LINKS.put(
            hash,
            key,
            putOptions
          );

        }


        return json({

          key: "/" + key

        });

      }


      // ========================================================
      // SHORT URL REDIRECT
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

        // Do not use caches.default.
        // Read KV directly with a 30-second cache TTL.
        const target = await env.LINKS.get(
          path,
          { cacheTtl: 30 }
        );


        if (target !== null) {

          return new Response(null, {

            status: 302,

            headers: {

              Location: target,

              "Cache-Control": "no-store, max-age=0"

            }

          });

        }


        return new Response(
          "404 Not Found",
          {

            status: 404,

            headers: {
              "Cache-Control": "no-store, max-age=0"
            }

          }
        );

      }


      // ========================================================
      // DEFAULT PAGE
      // ========================================================

      if (
        request.method !== "GET" &&
        request.method !== "HEAD"
      ) {

        return new Response(
          "Method Not Allowed",
          { status: 405 }
        );

      }


      return new Response(INDEX_HTML, {

        headers: {

          "Content-Type": "text/html; charset=UTF-8",

          "Cache-Control": "no-store, max-age=0"

        }

      });


    } catch (error) {

      // Log detailed errors only in Worker logs.
      // Do not expose stack traces to visitors.
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
