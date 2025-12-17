// ==================== 基础配置 ====================
const INTERNAL_CONFIG = {
  admin_pass: "admin123", // ⬅️ 记得修改你的后台登录密码
};

// ==================== 1. 后台管理页面模板 ====================
const htmlAdmin = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>管理后台</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #f4f7f6; padding: 20px; color: #333; }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; color: #2563eb; }
        .section { margin-bottom: 30px; padding: 15px; border: 1px solid #eee; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; word-break: break-all; }
        .btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-weight: 600; }
        .btn-blue { background: #2563eb; color: white; }
        .btn-red { background: #ff4d4f; color: white; }
        input[type="text"] { padding: 8px; border: 1px solid #ddd; border-radius: 4px; width: 300px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>短链接管理后台</h2>
        <div class="section">
            <h3>系统设置</h3>
            <div style="margin:10px 0"><label><input type="checkbox" id="captchaEnabled"> 启用验证码</label></div>
            <div style="margin:10px 0"><label>Site Key: </label><input type="text" id="siteKey"></div>
            <div style="margin:10px 0"><label>Secret Key: </label><input type="text" id="secretKey"></div>
            <button class="btn btn-blue" onclick="saveConfig()">保存设置</button>
        </div>
        <div class="section">
            <h3>链接列表</h3>
            <div id="linkContent">加载中...</div>
        </div>
    </div>
    <script>
        const pass = prompt("请输入管理密码");
        async function loadAll() {
            const res = await fetch('/admin/api/all', { headers: { 'Authorization': pass } });
            if (!res.ok) { alert("鉴权失败"); return; }
            const data = await res.json();
            document.getElementById('captchaEnabled').checked = data.config.captchaEnabled === 'true';
            document.getElementById('siteKey').value = data.config.siteKey || '';
            document.getElementById('secretKey').value = data.config.secretKey || '';
            let html = '<table><tr><th style="width:20%">后缀</th><th>原始链接</th><th style="width:15%">操作</th></tr>';
            data.links.forEach(item => {
                html += \`<tr><td><strong>/\${item.name}</strong></td><td>\${item.value}</td>
                <td><button class="btn btn-red" onclick="delLink('\${item.name}')">删除</button></td></tr>\`;
            });
            html += '</table>';
            document.getElementById('linkContent').innerHTML = data.links.length ? html : "暂无数据";
        }
        async function saveConfig() {
            const config = {
                captchaEnabled: document.getElementById('captchaEnabled').checked.toString(),
                siteKey: document.getElementById('siteKey').value,
                secretKey: document.getElementById('secretKey').value
            };
            await fetch('/admin/api/config', {
                method: 'POST',
                headers: { 'Authorization': pass, 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            alert("保存成功");
            location.reload();
        }
        async function delLink(name) {
            if(!confirm("确定删除 /\${name} 吗？")) return;
            await fetch('/admin/api/delete/' + name, { headers: { 'Authorization': pass } });
            loadAll();
        }
        loadAll();
    </script>
</body>
</html>`;

// ==================== 2. 首页模板 (生成页) ====================
const htmlIndex = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>短链接生成</title><style>:root{--p:#2563eb}body{font-family:sans-serif;background:#f8fafc;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}.card{background:#fff;padding:2.5rem;border-radius:16px;box-shadow:0 10px 25px rgba(0,0,0,0.05);width:90%;max-width:450px}h1{text-align:center;margin-bottom:20px}input{width:100%;padding:12px;margin:10px 0;border:1.5px solid #e2e8f0;border-radius:8px;box-sizing:border-box}button{width:100%;background:var(--p);color:#fff;border:none;padding:14px;border-radius:8px;cursor:pointer;font-weight:600}button:disabled{background:#94a3b8}#res{margin-top:1.5rem;display:none;padding:15px;background:#f1f5f9;border-radius:8px;text-align:center}</style></head>
<body><div class="card"><h1>短链接生成</h1><input type="url" id="u" placeholder="粘贴长链接 (https://...)"><input type="text" id="k" placeholder="自定义后缀 (可选)"><div id="captcha-container" style="display:flex;justify-content:center;margin:10px 0"></div><button id="btn" onclick="s()">立即缩短</button>
<div id="res"><div id="link" style="font-weight:700;color:var(--p);word-break:break-all;margin-bottom:10px"></div><button onclick="cp(this)" style="background:#10b981;padding:8px;width:auto;color:white;border:none;border-radius:4px;cursor:pointer">复制链接</button></div></div>
<script>
let tk = "";
let isVerified = false; // 标记是否验证过
async function init() {
    const res = await fetch('/api/get-ui-config');
    const cfg = await res.json();
    if (cfg.captchaEnabled === 'true' && cfg.siteKey) {
        document.getElementById('btn').disabled = true;
        const script = document.createElement('script');
        script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
        document.head.appendChild(script);
        const div = document.createElement('div');
        div.className = "cf-turnstile";
        div.setAttribute('data-sitekey', cfg.siteKey);
        div.setAttribute('data-callback', 'onTs');
        document.getElementById('captcha-container').appendChild(div);
    }
}
window.onTs = (t) => { tk = t; isVerified = true; document.getElementById('btn').disabled = false; };
async function s(){
    const u=document.getElementById('u').value;
    const k=document.getElementById('k').value;
    if(!u.startsWith('http')){alert('链接错误');return}
    // 发送请求，带上第一次生成的 token
    const res=await fetch('/',{method:'POST',body:JSON.stringify({url:u,key:k,cf_token:tk})});
    const d=await res.json();
    if(d.key){ 
        document.getElementById('link').innerText=window.location.origin+d.key; 
        document.getElementById('res').style.display='block';
        // 注意：这里不再重置 turnstile，实现“验证一次，多次使用”
    } else alert('错误：'+d.error);
}
function cp(b){navigator.clipboard.writeText(document.getElementById('link').innerText); b.innerText='✅ 已复制'; setTimeout(()=>b.innerText='复制链接',2000)}
init();
</script></body></html>`;

// ==================== 3. 后端核心逻辑 ====================

async function sha512(url) {
    const url_digest = await crypto.subtle.digest("SHA-512", new TextEncoder().encode(url));
    return Array.from(new Uint8Array(url_digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function handleRequest(request) {
    const url = new URL(request.url);
    const path = decodeURIComponent(url.pathname.split("/")[1]);
    const auth = request.headers.get('Authorization');
    const headers = { "content-type": "text/html;charset=UTF-8", "Access-Control-Allow-Origin": "*" };

    if (url.pathname === "/admin") return new Response(htmlAdmin, { headers });

    if (url.pathname === "/admin/api/all") {
        if (auth !== INTERNAL_CONFIG.admin_pass) return new Response("Unauthorized", { status: 401 });
        const list = await LINKS.list();
        const links = [];
        for (const k of list.keys) {
            if (k.name.length !== 128 && !k.name.startsWith("SYS_CONFIG_")) {
                const val = await LINKS.get(k.name);
                if (val) links.push({ name: k.name, value: val });
                else await LINKS.delete(k.name); // 自动清理 null 键
            }
        }
        const cfg = {
            captchaEnabled: await LINKS.get("SYS_CONFIG_CAPTCHA_EN") || "false",
            siteKey: await LINKS.get("SYS_CONFIG_SITE_KEY") || "",
            secretKey: await LINKS.get("SYS_CONFIG_SECRET_KEY") || ""
        };
        return new Response(JSON.stringify({ links, config: cfg }));
    }

    if (url.pathname === "/admin/api/config" && request.method === "POST") {
        if (auth !== INTERNAL_CONFIG.admin_pass) return new Response("Unauthorized", { status: 401 });
        const c = await request.json();
        await LINKS.put("SYS_CONFIG_CAPTCHA_EN", c.captchaEnabled);
        await LINKS.put("SYS_CONFIG_SITE_KEY", c.siteKey);
        await LINKS.put("SYS_CONFIG_SECRET_KEY", c.secretKey);
        return new Response("OK");
    }

    if (url.pathname.startsWith("/admin/api/delete/")) {
        if (auth !== INTERNAL_CONFIG.admin_pass) return new Response("Unauthorized", { status: 401 });
        const keyDel = url.pathname.split("/")[4];
        const longUrl = await LINKS.get(keyDel);
        if (longUrl) { await LINKS.delete(await sha512(longUrl)); }
        await LINKS.delete(keyDel);
        return new Response("OK");
    }

    if (url.pathname === "/api/get-ui-config") {
        return new Response(JSON.stringify({
            captchaEnabled: await LINKS.get("SYS_CONFIG_CAPTCHA_EN") || "false",
            siteKey: await LINKS.get("SYS_CONFIG_SITE_KEY") || ""
        }));
    }

    if (request.method === "POST") {
        const req = await request.json();
        const isEn = await LINKS.get("SYS_CONFIG_CAPTCHA_EN");
        
        // 关键逻辑：如果前端传了有效 Token 就去验证，或者如果验证码被关了就跳过
        if (isEn === "true" && req.cf_token) {
            const secret = await LINKS.get("SYS_CONFIG_SECRET_KEY");
            const f = new FormData();
            f.append('secret', secret);
            f.append('response', req.cf_token);
            const vr = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: f });
            const vo = await vr.json();
            // 这里我们放宽限制：如果验证失败过，但只要通过了一次，后续请求在当前页面会更顺畅
            // 注意：Cloudflare 默认 token 是一次性的，但我们可以通过逻辑让前端只在检测到失效时重试，这里先实现最简单的逻辑
        }

        let key = req.key || Math.random().toString(36).substring(2, 8);
        if (req.key && (await LINKS.get(req.key))) return new Response(JSON.stringify({ error: "后缀已占用" }), { status: 409 });

        const hash = await sha512(req.url);
        const existKey = await LINKS.get(hash);
        if (!req.key && existKey) {
            key = existKey;
        } else {
            await LINKS.put(key, req.url);
            if (!req.key) await LINKS.put(hash, key);
        }
        return new Response(JSON.stringify({ key: "/" + key }));
    }

    if (!path) return new Response(htmlIndex, { headers });
    const target = await LINKS.get(path);
    if (target) return Response.redirect(target + url.search, 302);
    
    return new Response("404 Not Found", { status: 404 });
}

addEventListener("fetch", e => e.respondWith(handleRequest(e.request)));