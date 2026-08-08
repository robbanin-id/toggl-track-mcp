// Toggl Track MCP — multi-tenant, OAuth 2.1 (PKCE + DCR), bring-your-own Toggl API token.
// Users authorize by pasting their own Toggl API token + selecting a workspace.
// Per-user cache keyed by hash(toggl_token + workspace_id). Toggl token stored encrypted at rest.

const ACCESS_TTL  = 3600;      // 1 hour
const REFRESH_TTL = 2592000;   // 30 days
const CODE_TTL    = 600;       // 10 min
const MCP_PROTOCOL = '2025-03-26';
const TOGGL_BASE = 'https://api.track.toggl.com/api/v9';
const REPORTS_BASE = 'https://api.track.toggl.com/reports/api/v3';

// Cache tiers (per Toggl account)
const IMMUTABLE_TTL = 2592000000; // 30d — past days immutable
const TODAY_TTL     = 3600000;    // 60m — current day mutable edge
const WARM_DAYS     = 10;         // widen narrow reads to a 10-day block
const MAX_ENTRIES   = 50000; // soft safety ceiling; raw response page cap remains 1000

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,MCP-Protocol-Version',
};

// ─── Crypto & util (reused from discord-mcp OAuth harness) ───────────────────
async function sha256(msg) {
  const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2,'0')).join('');
}
function randomHex(n = 32) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2,'0')).join('');
}
function hex2buf(h) { return new Uint8Array(h.match(/.{1,2}/g).map(b => parseInt(b,16))); }
function buf2hex(b) { return [...b].map(x => x.toString(16).padStart(2,'0')).join(''); }
async function getEncryptionKey(env) {
  const key = String(env.ENCRYPTION_KEY || '').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(key)) throw new Error('OAuth encryption is not configured safely');
  return key;
}
async function encrypt(plain, env) {
  const keyHex = await getEncryptionKey(env);
  const key = await crypto.subtle.importKey('raw', hex2buf(keyHex), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(plain));
  return buf2hex(iv) + ':' + buf2hex(new Uint8Array(enc));
}
async function decrypt(data, env) {
  const keyHex = await getEncryptionKey(env);
  const parts = String(data || '').split(':');
  if (parts.length !== 2 || !/^[0-9a-fA-F]+$/.test(parts[0]) || !/^[0-9a-fA-F]+$/.test(parts[1])) throw new Error('Invalid encrypted credential');
  const key = await crypto.subtle.importKey('raw', hex2buf(keyHex), 'AES-GCM', false, ['decrypt']);
  const dec = await crypto.subtle.decrypt({ name:'AES-GCM', iv:hex2buf(parts[0]) }, key, hex2buf(parts[1]));
  return new TextDecoder().decode(dec);
}
async function sha256hex(msg) { return await sha256(msg); }
function b64urlBytes(bytes) { return btoa(String.fromCharCode(...bytes)).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_'); }
async function pkceS256(verifier) { return b64urlBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))); }
function validPkceVerifier(v) { return typeof v === 'string' && /^[A-Za-z0-9\-\._~]{43,128}$/.test(v); }
function validPkceChallenge(v) { return typeof v === 'string' && /^[A-Za-z0-9_-]{43}$/.test(v); }
function safeUrl(value) { try { return new URL(String(value)); } catch { return null; } }
function validRedirectUri(value) {
  const u = safeUrl(value);
  return !!u && u.protocol === 'https:' && !u.username && !u.password && !u.hash && u.href.length <= 2048;
}
function jsonError(error, description, status=400) { return json({ error, error_description: description }, status); }
async function oauthStateCall(env, key, op, record, ttlSeconds) {
  if (!env.OAUTH_STATE) throw new Error('OAuth state storage is not configured');
  const id = env.OAUTH_STATE.idFromName(String(key));
  const stub = env.OAUTH_STATE.get(id);
  const r = await stub.fetch('https://oauth-state.internal/' + encodeURIComponent(String(key)), { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ op, record, ttl:ttlSeconds || CODE_TTL }) });
  if (!r.ok) throw new Error('OAuth state storage failure');
  const d = await r.json();
  if (!d.ok) throw new Error(d.error || 'OAuth state storage failure');
  return d.value;
}
async function oauthStateCreate(env, key, record, ttlSeconds) { return await oauthStateCall(env, key, 'create', record, ttlSeconds); }
async function oauthStateGet(env, key) { return await oauthStateCall(env, key, 'get'); }
async function oauthStateConsume(env, key) { return await oauthStateCall(env, key, 'consume'); }
async function oauthStateRevoke(env, key) { return await oauthStateCall(env, key, 'revoke'); }

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...CORS, ...headers } });
}
function html(body, status = 200, headers = {}) {
  return new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', ...CORS, ...headers } });
}
function redirect(url) { return Response.redirect(url, 302); }
async function kvGet(env, key) {
  const v = await env.TOGGL_MCP_KV.get(key);
  return v ? JSON.parse(v) : null;
}
async function kvPut(env, key, val, ttl) {
  const opts = ttl ? { expirationTtl: ttl } : {};
  await env.TOGGL_MCP_KV.put(key, JSON.stringify(val), opts);
}
async function kvGetRaw(env, key) { return await env.TOGGL_MCP_KV.get(key); }
async function kvPutRaw(env, key, val, ttl) {
  const opts = ttl ? { expirationTtl: ttl } : {};
  await env.TOGGL_MCP_KV.put(key, val, opts);
}
async function kvDel(env, key) { await env.TOGGL_MCP_KV.delete(key); }

// ─── Toggl API helpers ───────────────────────────────────────────────────────
function togglAuthHeader(token) { return 'Basic ' + btoa(token + ':api_token'); }
// Validate a Toggl API token; returns {id, fullname, default_workspace_id} or null. NEVER log the token.
async function togglMe(token) {
  try {
    const r = await fetch(TOGGL_BASE + '/me', { headers: { Authorization: togglAuthHeader(token), 'Content-Type': 'application/json' } });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}
async function togglWorkspaces(token) {
  try {
    const r = await fetch(TOGGL_BASE + '/workspaces', { headers: { Authorization: togglAuthHeader(token), 'Content-Type': 'application/json' } });
    if (!r.ok) return [];
    const w = await r.json();
    return Array.isArray(w) ? w.map(x => ({ id: x.id, name: x.name })) : [];
  } catch { return []; }
}

// ─── OAuth metadata (RFC 8414 / RFC 9728) ────────────────────────────────────
const OAUTH_META = (base) => ({
  issuer: base,
  authorization_endpoint: base + '/authorize',
  token_endpoint: base + '/token',
  revocation_endpoint: base + '/revoke',
  registration_endpoint: base + '/register',
  resource_indicators_supported: true,
  scopes_supported: ['mcp'],
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['none'],
});
const RESOURCE_META = (base) => ({
  resource: base + '/mcp',
  authorization_servers: [base],
  scopes_supported: ['mcp'],
  bearer_methods_supported: ['header'],
});

// ─── Authorize page (bring-your-own Toggl token) ─────────────────────────────
function AUTHORIZE_PAGE(params) {
  const tx = JSON.stringify(String(params.transaction_id || '')).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026');
  const nonce = String(params.csp_nonce || '');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect Toggl Track</title>
<style nonce="${nonce}">
:root{color-scheme:light dark}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:440px;margin:6vh auto;padding:0 20px;line-height:1.5}h1{font-size:1.35rem;margin-bottom:.25rem}.sub{color:#666;font-size:.9rem;margin-bottom:1.5rem}label{display:block;font-weight:600;margin:1rem 0 .35rem;font-size:.9rem}input,select{width:100%;padding:.6rem .7rem;font-size:1rem;border:1px solid #ccc;border-radius:8px;box-sizing:border-box;background:transparent;color:inherit}button{margin-top:1.25rem;width:100%;padding:.7rem;font-size:1rem;font-weight:600;border:0;border-radius:8px;background:#e57cd8;color:#111;cursor:pointer}button:disabled{opacity:.5;cursor:not-allowed}.err{color:#c0392b;font-size:.85rem;margin-top:.5rem;min-height:1em}.hint{font-size:.8rem;color:#888;margin-top:.3rem}a{color:#c86bc0}.step2{display:none}
</style></head><body>
<h1>Connect your Toggl Track</h1>
<div class="sub">This connects an AI client to <b>your own</b> Toggl account. Your API token is encrypted and never shared with the AI client.</div>
<div id="step1"><label for="tok">Toggl API Token</label><input id="tok" type="password" placeholder="Paste your Toggl API token" autocomplete="off"><div class="hint">Find it at <a href="https://track.toggl.com/profile" target="_blank" rel="noopener noreferrer">track.toggl.com/profile</a> → API Token.</div><button id="fetchBtn" type="button">Fetch my workspaces</button><div class="err" id="err1" role="alert"></div></div>
<div id="step2" class="step2"><label for="ws">Workspace</label><select id="ws"></select><div class="hint" id="whoami"></div><button id="connectBtn" type="button">Connect</button><div class="err" id="err2" role="alert"></div></div>
<form id="finalForm" method="POST" action="/authorize" style="display:none"><input type="hidden" name="transaction_id" id="f_tx"><input type="hidden" name="validation_id" id="f_val"><input type="hidden" name="workspace_id" id="f_ws"></form>
<script nonce="${nonce}">
(function(){var TX_ID=${tx},tokEl=document.getElementById('tok'),wsEl=document.getElementById('ws'),validationId='';
document.getElementById('fetchBtn').addEventListener('click',async function(){var btn=this,e1=document.getElementById('err1');e1.textContent='';var t=tokEl.value.trim();if(!t){e1.textContent='Please paste your token.';return;}btn.disabled=true;btn.textContent='Checking...';try{var r=await fetch('/api/validate-toggl',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({transaction_id:TX_ID,token:t})});var d=await r.json();if(!r.ok||!d.ok){e1.textContent=d.error||'Invalid token.';btn.disabled=false;btn.textContent='Fetch my workspaces';return;}validationId=d.validation_id;while(wsEl.firstChild)wsEl.removeChild(wsEl.firstChild);(d.workspaces||[]).forEach(function(w){var o=document.createElement('option');o.value=String(w.id);o.textContent=String(w.name||w.id);wsEl.appendChild(o);});tokEl.value='';document.getElementById('whoami').textContent='Signed in as '+(d.fullname||'Toggl user');document.getElementById('step1').style.display='none';document.getElementById('step2').style.display='block';}catch(e){e1.textContent='Network error. Try again.';btn.disabled=false;btn.textContent='Fetch my workspaces';}});
document.getElementById('connectBtn').addEventListener('click',function(){var e2=document.getElementById('err2');e2.textContent='';if(!validationId||!wsEl.value){e2.textContent='Choose a workspace.';return;}document.getElementById('f_tx').value=TX_ID;document.getElementById('f_val').value=validationId;document.getElementById('f_ws').value=wsEl.value;document.getElementById('finalForm').submit();});})();
</script></body></html>`;
}

// ─── OAuth handler ───────────────────────────────────────────────────────────
async function issueOAuthTokens(env, grantId, grant, clientId, resource) {
  const accessToken = randomHex(32), refreshToken = randomHex(32);
  const now = Date.now();
  await kvPut(env, 'token:' + await sha256(accessToken), { grant_id:grantId, type:'access', client_id:clientId, resource, expires_at:now + ACCESS_TTL*1000 }, ACCESS_TTL);
  await oauthStateCreate(env, 'refresh:' + await sha256(refreshToken), { grant_id:grantId, type:'refresh', client_id:clientId, resource, expires_at:now + REFRESH_TTL*1000 }, REFRESH_TTL);
  return { access_token:accessToken, token_type:'Bearer', expires_in:ACCESS_TTL, refresh_token:refreshToken, scope:'mcp' };
}
async function handleOAuth(request, env, url) {
  const base = String(env.BASE_URL || '').replace(/\/$/,'');
  const path = url.pathname;
  if (path === '/.well-known/oauth-authorization-server') return json(OAUTH_META(base));
  if (path === '/.well-known/oauth-protected-resource') return json(RESOURCE_META(base));

  if (path === '/register' && request.method === 'POST') {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown', rlKey = 'rl:reg:' + ip;
    const cnt = Number(await kvGet(env, rlKey) || 0); if (cnt >= 20) return jsonError('rate_limited','Too many registrations',429); await kvPut(env, rlKey, cnt + 1, 3600);
    let body = {}; try { body = await request.json(); } catch { return jsonError('invalid_client_metadata','JSON body required'); }
    const redirectUris = body.redirect_uris;
    if (!Array.isArray(redirectUris) || !redirectUris.length || redirectUris.length > 10 || !redirectUris.every(u => validRedirectUri(u))) return jsonError('invalid_redirect_uri','redirect_uris must contain only exact HTTPS URIs');
    const clientId = randomHex(16), client = { client_id:clientId, client_name:String(body.client_name || 'MCP Client').slice(0,120), redirect_uris:[...redirectUris], grant_types:['authorization_code','refresh_token'], response_types:['code'], token_endpoint_auth_method:'none', created_at:Date.now() };
    await kvPut(env, 'client:' + clientId, client); return json(client,201);
  }

  if (path === '/authorize' && request.method === 'GET') {
    const q = url.searchParams, clientId=q.get('client_id')||'', redirectUri=q.get('redirect_uri')||'', state=q.get('state')||'', responseType=q.get('response_type')||'', challenge=q.get('code_challenge')||'', method=q.get('code_challenge_method')||'', resource=q.get('resource')||'', scope=q.get('scope')||'mcp';
    const client = clientId ? await kvGet(env,'client:' + clientId) : null;
    if (!client) return jsonError('invalid_request','Unknown client_id');
    if (responseType !== 'code') return jsonError('unsupported_response_type','Only response_type=code is supported');
    if (!state) return jsonError('invalid_request','state is required');
    if (!client.redirect_uris.includes(redirectUri) || !validRedirectUri(redirectUri)) return jsonError('invalid_request','redirect_uri is not registered for this client');
    if (method !== 'S256' || !validPkceChallenge(challenge)) return jsonError('invalid_request','PKCE S256 code_challenge is required');
    if (resource !== base + '/mcp') return jsonError('invalid_target','resource must be the MCP endpoint');
    if (scope !== 'mcp') return jsonError('invalid_scope','Only scope=mcp is supported');
    const transactionId = randomHex(32);
    await oauthStateCreate(env,'tx:' + transactionId,{ type:'authorization_request', client_id:clientId, redirect_uri:redirectUri, state, code_challenge:challenge, code_challenge_method:'S256', resource, scope, created_at:Date.now() },CODE_TTL);
    const nonce = randomHex(16);
    return html(AUTHORIZE_PAGE({transaction_id:transactionId,csp_nonce:nonce}),200,{ 'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer', 'X-Content-Type-Options':'nosniff', 'Content-Security-Policy':"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" });
  }

  if (path === '/authorize' && request.method === 'POST') {
    let form; try { form = await request.formData(); } catch { return html('Invalid form.',400); }
    const transactionId=String(form.get('transaction_id')||''), validationId=String(form.get('validation_id')||''), workspaceId=String(form.get('workspace_id')||'');
    if (!/^[0-9a-f]{64}$/.test(transactionId) || !/^[0-9a-f]{64}$/.test(validationId) || !/^\d+$/.test(workspaceId)) return html('Invalid authorization transaction.',400);
    const tx=await oauthStateGet(env,'tx:'+transactionId), val=await oauthStateGet(env,'val:'+validationId);
    if (!tx || tx.type!=='authorization_request' || !val || val.type!=='toggl_validation' || val.transaction_id!==transactionId) return html('Authorization session expired. Restart the connection.',400);
    const ws=(val.workspaces||[]).find(x=>String(x.id)===workspaceId); if(!ws) return html('Workspace is not available for this token.',400);
    const code=randomHex(32), codeHash=await sha256(code);
    await oauthStateCreate(env,'code:'+codeHash,{ type:'authorization_code', client_id:tx.client_id, redirect_uri:tx.redirect_uri, resource:tx.resource, scope:tx.scope, code_challenge:tx.code_challenge, code_challenge_method:tx.code_challenge_method, toggl_token_enc:val.toggl_token_enc, workspace_id:String(ws.id), workspace_name:String(ws.name||''), toggl_user_id:val.toggl_user_id, toggl_timezone:val.toggl_timezone||null, created_at:Date.now() },CODE_TTL);
    await oauthStateRevoke(env,'tx:'+transactionId); await oauthStateRevoke(env,'val:'+validationId);
    const cb=new URL(tx.redirect_uri); cb.searchParams.set('code',code); cb.searchParams.set('state',tx.state); return redirect(cb.toString());
  }

  if (path === '/token' && request.method === 'POST') {
    let form; try { form=await request.formData(); } catch { return jsonError('invalid_request','Form body required'); }
    const grantType=String(form.get('grant_type')||''), clientId=String(form.get('client_id')||''), resource=String(form.get('resource')||'');
    if (grantType==='authorization_code') {
      const code=String(form.get('code')||''), redirectUri=String(form.get('redirect_uri')||''), verifier=String(form.get('code_verifier')||'');
      if(!/^[0-9a-f]{64}$/.test(code)||!clientId||!validRedirectUri(redirectUri)||resource!==base+'/mcp'||!validPkceVerifier(verifier)) return jsonError('invalid_grant','Invalid authorization code request');
      const key='code:'+await sha256(code), authReq=await oauthStateGet(env,key);
      if(!authReq||authReq.type!=='authorization_code'||authReq.client_id!==clientId||authReq.redirect_uri!==redirectUri||authReq.resource!==resource) return jsonError('invalid_grant','Authorization code binding failed');
      if(await pkceS256(verifier)!==authReq.code_challenge) return jsonError('invalid_grant','PKCE verification failed');
      const consumed=await oauthStateConsume(env,key); if(!consumed) return jsonError('invalid_grant','Authorization code already used or expired');
      const grantId=randomHex(16), grant={toggl_token_enc:consumed.toggl_token_enc,workspace_id:consumed.workspace_id,workspace_name:consumed.workspace_name,toggl_user_id:consumed.toggl_user_id,toggl_timezone:consumed.toggl_timezone||null,client_id:clientId,resource,scope:'mcp',created_at:Date.now(),expires_at:Date.now()+(REFRESH_TTL+3600)*1000};
      await kvPut(env,'grant:'+grantId,grant,REFRESH_TTL+3600); return json(await issueOAuthTokens(env,grantId,grant,clientId,resource));
    }
    if(grantType==='refresh_token') {
      const refreshToken=String(form.get('refresh_token')||''); if(!clientId||resource!==base+'/mcp'||!refreshToken) return jsonError('invalid_grant','Refresh token binding failed');
      const key='refresh:'+await sha256(refreshToken), stored=await oauthStateGet(env,key); if(!stored||stored.type!=='refresh'||stored.client_id!==clientId||stored.resource!==resource||stored.expires_at<Date.now()) return jsonError('invalid_grant','Refresh token invalid or expired');
      const consumed=await oauthStateConsume(env,key); if(!consumed) return jsonError('invalid_grant','Refresh token already used or expired');
      const grant=await kvGet(env,'grant:'+consumed.grant_id); if(!grant||grant.revoked_at||(grant.expires_at&&grant.expires_at<Date.now())) return jsonError('invalid_grant','Grant revoked or expired');
      return json(await issueOAuthTokens(env,consumed.grant_id,grant,clientId,resource));
    }
    return jsonError('unsupported_grant_type','Only authorization_code and refresh_token are supported');
  }

  if(path==='/revoke'&&request.method==='POST') {
    let form; try{form=await request.formData();}catch{return json({},200);} const token=String(form.get('token')||''); if(!token)return json({},200);
    const hash=await sha256(token), access=await kvGet(env,'token:'+hash); if(access) await kvDel(env,'token:'+hash);
    const refresh=await oauthStateGet(env,'refresh:'+hash); if(refresh){await oauthStateRevoke(env,'refresh:'+hash);const grant=await kvGet(env,'grant:'+refresh.grant_id);if(grant&&!grant.revoked_at){grant.revoked_at=Date.now();await kvPut(env,'grant:'+refresh.grant_id,grant,REFRESH_TTL+3600);}}
    return json({},200);
  }
  return null;
}

// Validate-toggl endpoint used by the authorize page (returns workspaces). NEVER log token.
async function handleValidateToggl(request, env) {
  let body={}; try{body=await request.json();}catch{return json({ok:false,error:'Invalid request'},400);}
  const transactionId=String(body.transaction_id||''), token=String(body.token||'').trim();
  if(!/^[0-9a-f]{64}$/.test(transactionId)||!token||token.length>512||/[\u0000-\u001f\u007f]/.test(token)) return json({ok:false,error:'Invalid authorization request'},400);
  const ip=request.headers.get('CF-Connecting-IP')||'unknown', rlKey='rl:validate:'+ip, cnt=Number(await kvGet(env,rlKey)||0); if(cnt>=10)return json({ok:false,error:'Too many validation attempts'},429); await kvPut(env,rlKey,cnt+1,3600);
  const tx=await oauthStateGet(env,'tx:'+transactionId); if(!tx||tx.type!=='authorization_request') return json({ok:false,error:'Authorization session expired'},400);
  const me=await togglMe(token); if(!me)return json({ok:false,error:'Invalid token'},400);
  const workspaces=await togglWorkspaces(token); if(!workspaces.length)return json({ok:false,error:'No accessible workspaces'},400);
  const validationId=randomHex(32); const togglTokenEnc=await encrypt(token,env);
  await oauthStateCreate(env,'val:'+validationId,{type:'toggl_validation',transaction_id:transactionId,toggl_token_enc:togglTokenEnc,toggl_user_id:me.id,toggl_timezone:me.timezone||null,fullname:me.fullname||null,default_workspace_id:me.default_workspace_id||null,workspaces},CODE_TTL);
  return json({ok:true,validation_id:validationId,fullname:me.fullname||null,default_workspace_id:me.default_workspace_id||null,workspaces});
}

// Resolve grant → decrypted toggl credentials. NEVER log token.
async function authenticate(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const stored = await kvGet(env, 'token:' + await sha256(token));
  if (!stored || stored.type !== 'access') return null;
  if (stored.expires_at < Date.now()) return null;
  const grant = await kvGet(env, 'grant:' + stored.grant_id);
  if (!grant || grant.revoked_at || (grant.expires_at && grant.expires_at < Date.now())) return null;
  return grant;
}

// ─── Per-request Toggl context (multi-tenant, no shared globals) ─────────────
// All cache state lives in a ctx object keyed per Toggl account, persisted to KV.
function dayKey(ts, tz) {
  try { return new Intl.DateTimeFormat('en-CA', { timeZone: tz || 'UTC', year:'numeric', month:'2-digit', day:'2-digit' }).format(new Date(ts)); }
  catch { return String(ts).slice(0,10); }
}
function normalizeBounds(a, tz) {
  // Keep _startMs/_endMs time-precise, but force start_date/end_date to pure local YYYY-MM-DD.
  // Cache ranges / warm windows / fetch params must never hold datetime strings:
  // lexicographic comparison would let a half-day claim a whole day.
  a.start_date = dayKey(a._startMs, tz);
  a.end_date = dayKey(a._endMs - 1, tz);
  return a;
}
function dAdd(str, n) { return new Date(new Date(str+'T00:00:00Z').getTime() + n*86400000).toISOString().slice(0,10); }
function parseDateWithTz(str, tz) {
  if (!str) return new Date(NaN);
  if (/[TZ+-]/.test(str.slice(10))) return new Date(str);
  if (tz) try {
    const utc = Date.parse(str + 'T00:00:00Z');
    // derive offset for tz at that date via formatToParts
    const dtf = new Intl.DateTimeFormat('en-US', { timeZone: tz, year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false });
    const parts = dtf.formatToParts(new Date(utc));
    const o = {}; for (const p of parts) o[p.type] = p.value;
    const asUTC = Date.UTC(+o.year, +o.month-1, +o.day, +(o.hour==='24'?0:o.hour), +o.minute, +o.second);
    const offset = asUTC - utc; // ms the wall-clock is ahead of UTC
    return new Date(utc - offset);
  } catch {}
  return new Date(str);
}
function endExclusiveMs(str, de) {
  if (str && /[TZ+-]/.test(String(str).slice(10))) return de.getTime();
  return de.getTime() + 86400000;
}
function rangeDays(a) {
  if (!a || !a.start_date || !a.end_date) return 0;
  return Math.floor((Date.parse(a.end_date+'T00:00:00Z') - Date.parse(a.start_date+'T00:00:00Z'))/86400000) + 1;
}
function warmWindow(reqS, reqE) {
  const e = new Date(reqE+'T00:00:00Z'), s = new Date(reqS+'T00:00:00Z');
  const days = Math.floor((e-s)/86400000)+1;
  if (days >= WARM_DAYS) return { s: reqS, e: reqE };
  const startCandidate = new Date(e.getTime() - (WARM_DAYS-1)*86400000);
  const finalS = startCandidate < s ? startCandidate : s;
  return { s: finalS.toISOString().slice(0,10), e: reqE };
}

// Toggl API call for a specific account (serialized-ish, with retry)
async function togglGet(token, path) {
  for (let i=0;i<3;i++) {
    const r = await fetch(TOGGL_BASE + path, { headers: { Authorization: togglAuthHeader(token), 'Content-Type':'application/json' } });
    const t = await r.text();
    let d; try { d = JSON.parse(t); } catch { d = t; }
    if (r.ok) return d;
    const reset=r.headers&&r.headers.get?r.headers.get('X-Toggl-Quota-Resets-In'):null, rem=r.headers&&r.headers.get?r.headers.get('X-Toggl-Quota-Remaining'):null;
    if(r.status===402)throw new Error('Toggl quota exhausted'+(reset?' (resets in '+reset+' seconds)':'')+(rem?' (remaining: '+rem+')':''));
    if(r.status===429||r.status>=500){if(i===2)throw new Error('Toggl '+r.status+(reset?' (retry after '+reset+' seconds)':''));await new Promise(res=>setTimeout(res,1100*(i+1)));continue;}
    throw new Error('Toggl '+r.status);
  }
  throw new Error('Toggl request failed after retries');
}
async function togglReportsRange(token, ws, a) {
  let out=[], row=1, nextId=null;
  for (let i=0;i<200;i++) {
    const body = { start_date:a.start_date, end_date:a.end_date, page_size:50, first_row_number:row, enrich_response:true };
    if (nextId) body.first_id = nextId;
    const r = await fetch(REPORTS_BASE + '/workspace/' + ws + '/search/time_entries', { method:'POST', headers:{ Authorization: togglAuthHeader(token), 'Content-Type':'application/json' }, body: JSON.stringify(body) });
    const txt = await r.text(); let d; try { d=JSON.parse(txt); } catch { d=txt; }
    if(r.status===402){const reset=r.headers.get('X-Toggl-Quota-Resets-In');throw new Error('Toggl Reports quota exhausted'+(reset?' (resets in '+reset+' seconds)':''));}
    if(!r.ok)throw new Error('Toggl Reports '+r.status);
    const arr = Array.isArray(d) ? d : (d?.time_entries || d?.data || []); out.push(...arr);
    const nr=r.headers.get('X-Next-Row-Number'),ni=r.headers.get('X-Next-ID'),remaining=Number(r.headers.get('X-Toggl-Quota-Remaining'));
    if(!arr.length||!nr||String(nr)===String(row))break;
    if(Number.isFinite(remaining)&&remaining<=1){out.partial=true;break;}
    row=Number(nr);nextId=ni||null;
  }
  const m = new Map(); for (const x of out) m.set(x.id, x); const result=[...m.values()]; if(out.partial) result.partial=true; return result;
}
async function togglFetchRange(token, ws, a, depth=0) {
  if (a && rangeDays(a) > 93) return togglReportsRange(token, ws, a);
  if (!a || !a.start_date || !a.end_date) return await togglGet(token, '/me/time_entries');
  const q = new URLSearchParams({ start_date:a.start_date, end_date:dAdd(a.end_date,1) });
  const e = await togglGet(token, '/me/time_entries?' + q);
  if (!Array.isArray(e) || e.length < 1000 || depth >= 8 || a.start_date===a.end_date) return e || [];
  const s = new Date(a.start_date+'T00:00:00Z'), z = new Date(a.end_date+'T00:00:00Z'), m = new Date(Math.floor((s.getTime()+z.getTime())/2));
  const mid = m.toISOString().slice(0,10), next = new Date(m.getTime()+86400000).toISOString().slice(0,10);
  const l = await togglFetchRange(token, ws, {start_date:a.start_date,end_date:mid}, depth+1);
  const r = await togglFetchRange(token, ws, {start_date:next,end_date:a.end_date}, depth+1);
  const mm = new Map(); for (const x of [...l,...r]) mm.set(x.id,x); const result=[...mm.values()]; if(l.partial||r.partial) result.partial=true; return result;
}

// ─── Per-account cache context ───────────────────────────────────────────────
// Key namespace: u:{acctHash}:entries / :projects / :tags . acctHash = sha256(token+ws).
async function makeCtx(env, grant) {
  const token = await decrypt(grant.toggl_token_enc, env);
  const ws = String(grant.workspace_id);
  const acctHash = await sha256(token + ':' + ws);
  return {
    env, token, ws, acctHash, profileTz: grant.toggl_timezone || null,
    kEntries: 'u:' + acctHash + ':entries',
    kProjects: 'u:' + acctHash + ':projects',
    kTags: 'u:' + acctHash + ':tags',
    entries: [], ranges: [], entriesAt: 0, todayAt: 0, incomplete: false,
    projects: null, tags: null,
    prov: { entries:'miss', projects:'miss', tags:'miss', upstream: [] },
  };
}
function todayStr(ctx, tz) { return dayKey(Date.now(), tz || 'UTC'); }
function coversRange(ranges, s, e) { return Array.isArray(ranges) && ranges.some(r => r.s <= s && r.e >= e); }
function unionRanges(ranges, extra) {
  let rs = (ranges||[]).concat(extra||[]).filter(r=>r&&r.s&&r.e).sort((a,b)=>a.s<b.s?-1:1);
  const merged = [];
  for (const r of rs) {
    if (!merged.length || r.s > dAdd(merged[merged.length-1].e, 1)) merged.push({s:r.s,e:r.e});
    else if (r.e > merged[merged.length-1].e) merged[merged.length-1].e = r.e;
  }
  return merged;
}
function mergeEntries(list, add) {
  const m = new Map(list.map(x=>[x.id,x]));
  for (const x of add) if (x && x.id != null) m.set(x.id, x);
  let out = [...m.values()].sort((a,b)=>String(a.start).localeCompare(String(b.start)));
  return out;
}
function findGaps(ranges, s, e) {
  const sorted = (ranges||[]).slice().filter(r=>r&&r.s&&r.e).sort((a,b)=>a.s<b.s?-1:1);
  const gaps = []; let cursor = s;
  for (const r of sorted) {
    if (r.e < cursor) continue;
    if (cursor < r.s) { let ge = dAdd(r.s,-1); if (ge>e) ge=e; gaps.push({s:cursor,e:ge}); }
    const na = dAdd(r.e,1); if (na>cursor) cursor = na;
    if (cursor > e) break;
  }
  if (cursor <= e) gaps.push({s:cursor,e:e});
  return gaps.filter(g=>g.s<=g.e && g.s<=e);
}
async function loadEntriesCache(ctx) {
  const raw = await kvGetRaw(ctx.env, ctx.kEntries);
  if (raw) {
    try {
      const kd = JSON.parse(raw);
      if (Array.isArray(kd.entries) && Array.isArray(kd.ranges)) {
        ctx.entries = kd.entries; ctx.ranges = kd.ranges;
        ctx.entriesAt = Number(kd.at)||0; ctx.todayAt = Number(kd.todayAt)||0; ctx.incomplete = !!kd.incomplete;
        ctx.prov.entries = 'kv_hit';
        return;
      }
    } catch {}
  }
  ctx.prov.entries = ctx.entries.length ? 'memory_hit' : 'miss';
}
async function saveEntriesCache(ctx) {
  await kvPutRaw(ctx.env, ctx.kEntries, JSON.stringify({ entries: ctx.entries, ranges: ctx.ranges, at: ctx.entriesAt, todayAt: ctx.todayAt, incomplete:!!ctx.incomplete }), 2592000);
}
async function ensureProjects(ctx) {
  if (ctx.projects) { ctx.prov.projects = 'memory_hit'; return; }
  const raw = await kvGetRaw(ctx.env, ctx.kProjects);
  if (raw) { try { const kd = JSON.parse(raw); if (kd && kd.map && (Date.now()-kd.at < IMMUTABLE_TTL)) { ctx.projects = kd.map; ctx.prov.projects='kv_hit'; return; } } catch {} }
  ctx.prov.projects = 'fetch'; ctx.prov.upstream.push('/workspaces/'+ctx.ws+'/projects');
  const p = await togglGet(ctx.token, '/workspaces/'+ctx.ws+'/projects');
  const map = {}; for (const x of (Array.isArray(p)?p:[])) map[x.id] = { id:x.id, name:x.name, color:x.color, active:x.active, billable:x.billable, client_id:x.client_id };
  ctx.projects = map;
  await kvPutRaw(ctx.env, ctx.kProjects, JSON.stringify({ map, at: Date.now() }), 2592000);
}
async function ensureTags(ctx) {
  if (ctx.tags) { ctx.prov.tags='memory_hit'; return; }
  const raw = await kvGetRaw(ctx.env, ctx.kTags);
  if (raw) { try { const kd = JSON.parse(raw); if (kd && (Date.now()-kd.at < IMMUTABLE_TTL)) { ctx.tags = kd.list; ctx.prov.tags='kv_hit'; return; } } catch {} }
  ctx.prov.tags = 'fetch'; ctx.prov.upstream.push('/workspaces/'+ctx.ws+'/tags');
  const t = await togglGet(ctx.token, '/workspaces/'+ctx.ws+'/tags');
  ctx.tags = Array.isArray(t)?t:[];
  await kvPutRaw(ctx.env, ctx.kTags, JSON.stringify({ list: ctx.tags, at: Date.now() }), 2592000);
}
async function ensureEntries(ctx, a, opts) {
  opts = opts || {};
  const force = !!opts.force;
  const tz = a.timezone || ctx.profileTz || 'UTC';
  const today = dayKey(Date.now(), tz);
  const reqS = a.start_date, reqE = a.end_date;
  const w = warmWindow(reqS, reqE);
  await loadEntriesCache(ctx);

  if (force) {
    ctx.prov.entries = 'fetch'; ctx.prov.upstream.push('/me/time_entries');
    const fd = await togglFetchRange(ctx.token, ctx.ws, { start_date: reqS, end_date: reqE });
    if (Array.isArray(fd)) {
      ctx.incomplete = !!fd.partial;
      ctx.entries = ctx.entries.filter(x => { const dk = dayKey(x.start, tz); return dk < reqS || dk > reqE; });
      ctx.entries = mergeEntries(ctx.entries, fd);
      ctx.ranges = unionRanges(ctx.ranges, [{s:reqS,e:reqE}]);
    }
    ctx.entriesAt = Date.now(); if (reqE >= today) ctx.todayAt = Date.now();
    await saveEntriesCache(ctx); return;
  }

  const pastEnd = reqE < today ? reqE : dAdd(today,-1);
  const immutableFresh = ctx.entriesAt && (Date.now() - ctx.entriesAt < IMMUTABLE_TTL);
  const pastCovered = (reqS > pastEnd) || (immutableFresh && coversRange(ctx.ranges, reqS, pastEnd));
  const touchesToday = reqE >= today;
  const todayCovered = (!touchesToday) || (ctx.todayAt && (Date.now()-ctx.todayAt < TODAY_TTL) && coversRange(ctx.ranges, today, today));

  if (ctx.entries.length && pastCovered && todayCovered) {
    ctx.prov.entries = ctx.prov.entries === 'kv_hit' ? 'kv_hit' : 'memory_hit'; return;
  }

  let gaps = findGaps(ctx.ranges, w.s, w.e);
  if (touchesToday && !todayCovered) {
    ctx.entries = ctx.entries.filter(x => dayKey(x.start, tz) !== today);
    if (!gaps.some(g => g.s <= today && g.e >= today)) gaps.push({ s: today, e: today });
  }
  if (!gaps.length) { ctx.prov.entries = ctx.prov.entries === 'kv_hit' ? 'kv_hit' : 'memory_hit'; return; }

  ctx.prov.entries = ctx.entries.length ? 'gap_fetch' : 'fetch';
  for (const g of gaps) {
    if (g.s > g.e) continue;
    ctx.prov.upstream.push('/me/time_entries');
    const part = await togglFetchRange(ctx.token, ctx.ws, { start_date: g.s, end_date: g.e });
    if (Array.isArray(part)) { ctx.entries = mergeEntries(ctx.entries, part); if(part.partial) ctx.incomplete=true; else ctx.ranges = unionRanges(ctx.ranges, [{s:g.s,e:g.e}]); }
  }
  ctx.entriesAt = Date.now(); if (touchesToday) ctx.todayAt = Date.now();
  await saveEntriesCache(ctx);
}
function effDuration(x) {
  const d=Number(x&&x.duration); if(Number.isFinite(d)&&d>=0)return d;
  const st=x&&x.start?new Date(x.start).getTime():NaN; if(!isNaN(st))return Math.max(0,Math.floor((Date.now()-st)/1000)); return 0;
}
function durationWithinWindow(x,a){
  const xs=x&&x.start?new Date(x.start).getTime():NaN, xe=x&&x.stop?new Date(x.stop).getTime():Date.now(); if(!Number.isFinite(xs)||!Number.isFinite(xe))return 0;
  const s=Math.max(xs,Number.isFinite(a._startMs)?a._startMs:xs), e=Math.min(xe,Number.isFinite(a._endMs)?a._endMs:xe); return e>s?Math.floor((e-s)/1000):0;
}
function filterByDate(ctx, entries, a) {
  let s = a._startMs || 0, e = a._endMs || Infinity;
  if (a.intersects_range && a._startMs) { s = a._startMs; e = a._endMs; }
  const pids = (a.project_ids||[]).map(Number);
  const names = (a.project_names||[]).map(String);
  const minDur = Number(a.min_duration_seconds) || 0;
  return entries.filter(x => {
    const xs = new Date(x.start).getTime();
    const xe = x.stop ? new Date(x.stop).getTime() : Infinity;
    if (isNaN(xs)) return false;
    const inRange = a.intersects_range ? (xs < e && xe >= s) : (xs >= s && xs < e);
    if (!inRange) return false;
    if (pids.length && !pids.includes(Number(x.project_id))) return false;
    if (names.length && !names.some(n => String(ctx.projects?.[x.project_id]?.name||'').toLowerCase() === n.toLowerCase())) return false;
    if (a.description_contains && !String(x.description||'').toLowerCase().includes(String(a.description_contains).toLowerCase())) return false;
    if (minDur > 0 && effDuration(x) < minDur) return false;
    return true;
  });
}
function localParts(ts, tz) {
  try {
    const dtf = new Intl.DateTimeFormat('en-CA', { timeZone: tz||'UTC', year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', hour12:false });
    const p = {}; for (const q of dtf.formatToParts(new Date(ts))) p[q.type]=q.value;
    return { date: p.year+'-'+p.month+'-'+p.day, time: (p.hour==='24'?'00':p.hour)+':'+p.minute };
  } catch { return { date: String(ts).slice(0,10), time: String(ts).slice(11,16) }; }
}
function filterDiagnostics(ctx, a) {
  const out = {};
  const names = (a.project_names || []).map(String);
  if (names.length && ctx.projects) {
    const all = Object.values(ctx.projects).map(p => p.name).filter(Boolean);
    const lower = all.map(n => n.toLowerCase());
    const unmatched = names.filter(n => lower.indexOf(n.toLowerCase()) === -1);
    if (unmatched.length) {
      const pre = [], sub = [];
      for (let i=0;i<all.length;i++) {
        const ln=lower[i];
        for (const u of unmatched) { const q=u.toLowerCase(); if(!q) continue; if(ln.indexOf(q)===0){pre.push(all[i]);break} if(ln.indexOf(q)>0){sub.push(all[i]);break} }
      }
      const ranked=pre.concat(sub), LIMIT=20;
      out.project_names_unmatched=unmatched; out.match_mode='exact (case-insensitive)'; out.available_similar=ranked.slice(0,LIMIT); out.similar_total=ranked.length;
      if(ranked.length>LIMIT){out.similar_truncated=true;out.note='Showing '+LIMIT+' of '+ranked.length+' similar project names (ranked: prefix matches first). Narrow the query text; do not call the project catalog because the primary tool already loaded project data.';}
    }
  }
  if (a.description_contains) {
    const base = {...a}; delete base.description_contains;
    const before = filterByDate(ctx, ctx.entries, base), matched = filterByDate(ctx, ctx.entries, a);
    if (!matched.length) {
      const qd=String(a.description_contains).toLowerCase(), counts={};
      for (const x of before) { const pid=String(x.project_id); counts[pid]=(counts[pid]||0)+1; }
      const projects=Object.values(ctx.projects||{}).filter(p=>p&&p.name).map(p=>{const n=String(p.name),ln=n.toLowerCase(),rank=ln.indexOf(qd)===0?0:(ln.indexOf(qd)>=0?1:2);return {project_id:p.id,project_name:n,entries_before_description_filter:counts[String(p.id)]||0,match_rank:rank};});
      const similar=projects.filter(p=>p.match_rank<2).sort((x,y)=>x.match_rank-y.match_rank||y.entries_before_description_filter-x.entries_before_description_filter||x.project_name.localeCompare(y.project_name));
      const fallback=projects.filter(p=>p.entries_before_description_filter>0).sort((x,y)=>y.entries_before_description_filter-x.entries_before_description_filter||x.project_name.localeCompare(y.project_name));
      const candidates=similar.length?similar:fallback, LIMIT=20;
      out.description_filter={query:a.description_contains,matched_entries:0,entries_before_description_filter:before.length,meaning:'description_contains searches entry descriptions only; zero matches do not prove the requested activity or project is absent.',candidate_projects:candidates.slice(0,LIMIT),candidate_projects_total:candidates.length,suggested_action:'If the intended activity is tracked as a project, retry with project_names using an exact project_name from candidate_projects. Do not call the project catalog; this response already loaded project data.'};
      if(candidates.length>LIMIT) out.description_filter.candidate_projects_truncated=true;
    }
  }
  return Object.keys(out).length ? out : undefined;
}
function dateFacts(entries, a, tz) {
  const shift = (a.day_anchor === 'next_day') ? 1 : 0;
  const counts = {};
  for (const x of entries) { let dk = dayKey(x.start, tz); if (shift) dk = dAdd(dk,1); counts[dk] = (counts[dk]||0)+1; }
  let s = a.start_date, e = a.end_date; if (shift) { s = dAdd(s,1); e = dAdd(e,1); }
  const missing=[], dup=[]; let cur=s, guard=0;
  while (cur <= e && guard++ < 400) { if (!counts[cur]) missing.push(cur); else if (counts[cur] > 1) dup.push(cur); cur = dAdd(cur,1); }
  return { basis: shift ? 'night_of (day_anchor=next_day)' : 'local start date', timezone: tz, missing_dates: missing, duplicate_dates: dup };
}
function shapeEntry(ctx, x, fields, tz, tzKnown) {
  const fs = Array.isArray(fields) && fields.length ? fields : ['id','start','stop','duration','description','project_id','tags'];
  const o = {};
  for (const f of fs) {
    if (f === 'project_name' || f === 'project.name') o.project_name = ctx.projects?.[x.project_id]?.name || null;
    else if (f === 'local_start_date' || f === 'local_start_time') { const lp = localParts(x.start, tz); const k = (tzKnown === false) ? (f==='local_start_date' ? 'utc_start_date' : 'utc_start_time') : f; o[k] = (f==='local_start_date') ? lp.date : lp.time; }
    else if (f === 'local_stop_date' || f === 'local_stop_time') { const k = (tzKnown === false) ? (f==='local_stop_date' ? 'utc_stop_date' : 'utc_stop_time') : f; if (x.stop) { const lp = localParts(x.stop, tz); o[k] = (f==='local_stop_date') ? lp.date : lp.time; } else o[k] = null; }
    else if (f in x) o[f] = x[f];
  }
  return o;
}
function cacheMeta(ctx, tz) {
  const today = dayKey(Date.now(), tz||'UTC');
  let maxStart=null, maxStop=null;
  for (const x of ctx.entries) { if (x.start && (!maxStart||x.start>maxStart)) maxStart=x.start; if (x.stop && (!maxStop||x.stop>maxStop)) maxStop=x.stop; }
  return {
    built_at: ctx.entriesAt ? new Date(ctx.entriesAt).toISOString() : null,
    today_built_at: ctx.todayAt ? new Date(ctx.todayAt).toISOString() : null,
    freshness_seconds: ctx.entriesAt ? Math.round((Date.now()-ctx.entriesAt)/1000) : null,
    entry_count: ctx.entries.length, max_start: maxStart, max_stop: maxStop,
    coverage: ctx.ranges || null, today_fresh: !!(ctx.todayAt && (Date.now()-ctx.todayAt < TODAY_TTL)), partial:!!ctx.incomplete,
  };
}

// ─── MCP tools ───────────────────────────────────────────────────────────────
function toolsList() {
  const D = {
    get_current_time_entry: 'Read the currently running Toggl time entry.',
    get_time_entries_with_project_tag: 'Get time entries for a date range. PRIMARY tool for reading time data. Entries are returned in CHRONOLOGICAL order (by start) and are PAGINATED (max 1000 per page). If meta.pagination.report_ready is false, the result is PARTIAL: do not produce a final report \u2014 either narrow the query with project_ids/project_names, or repeat the identical request with offset=meta.pagination.next_offset and merge every page first. Each entry includes: id, start, stop, duration, description, tags (tag names as strings), project_id. Project NAMES are in the top-level "projects" map of THIS SAME response — resolve via projects[project_id].name. No need to call browse_projects_catalog or browse_tags_catalog. NEVER infer coverage from entry count ("31 entries = 31 days" is INVALID) — read meta.date_facts.missing_dates / duplicate_dates. For overnight activities such as sleep, request fields [local_start_date, local_start_time, local_stop_time] or set day_anchor="next_day". Filter: project_ids, project_names, description_contains, min_duration_seconds, intersects_range. description_contains searches entry description text only, not project names; if it returns zero, inspect meta.filter_diagnostics and retry with an exact project_names value when appropriate. project_names is EXACT match (case-insensitive): projects whose names merely share a prefix or word are DIFFERENT projects and must not be treated as the same. Use names exactly as they appear in the projects map or get_summary groups; if a name does not match, meta.filter_diagnostics lists the unmatched name plus similar existing names \u2014 no catalog call needed.',
    get_summary: 'Return compact aggregated time totals instead of raw entries. Group by project, day, tag, or project_day. day/project_day group by the LOCAL date the entry STARTS (set day_anchor="next_day" for the night-of convention). Groups include project_id + project_name.',
    get_coverage: 'Authoritative way to find dates with NO entries: per-day counts, tracked seconds, gaps. Use this (or meta.date_facts) instead of inferring coverage from entry counts. Honors timezone and day_anchor.',
    browse_projects_catalog: 'Admin/inspection only. DO NOT CALL for reports/analysis/filtering — project id+name already appear in get_summary groups and the projects map of get_time_entries_with_project_tag. Only to list ALL projects.',
    browse_tags_catalog: 'Admin/inspection only. DO NOT CALL for reports — tag names already appear inside each entry. Only to list ALL tags.',
    create_time_entry: 'Create a Toggl time entry.',
    update_time_entry: 'Update an existing Toggl time entry.',
    stop_time_entry: 'Stop a running Toggl time entry.',
    delete_time_entry: 'Delete a Toggl time entry. Destructive.',
    create_project: 'Create a project in Toggl.',
    update_project: 'Update an existing Toggl project.',
    delete_project: 'Delete a Toggl project. Destructive.',
    create_tag: 'Create a Toggl tag.',
    update_tag: 'Rename an existing Toggl tag.',
    delete_tag: 'Delete a Toggl tag. Destructive.',
  };
  const rangeSchema = { type:'object', additionalProperties:false, properties:{
    start_date:{type:'string'}, end_date:{type:'string'}, project_ids:{type:'array',items:{type:'integer'}}, project_names:{type:'array',items:{type:'string'}},
    description_contains:{type:'string'}, min_duration_seconds:{type:'number',minimum:0}, intersects_range:{type:'boolean'}, fields:{type:'array',items:{type:'string'}}, limit:{type:'integer',minimum:1,maximum:1000,description:'Maximum entries per page. Default and maximum are 1000.'}, offset:{type:'integer',minimum:0}, timezone:{type:'string'}, day_anchor:{type:'string',enum:['start','next_day']}, force_refresh:{type:'boolean'}
  }, required:['start_date','end_date'] };
  const t = [
    {name:'get_current_time_entry',inputSchema:{type:'object',additionalProperties:false,properties:{}}},
    {name:'get_time_entries_with_project_tag',inputSchema:rangeSchema},
    {name:'get_summary',inputSchema:{type:'object',additionalProperties:false,properties:{start_date:{type:'string'},end_date:{type:'string'},group_by:{type:'string',enum:['project','day','tag','project_day']},project_ids:{type:'array',items:{type:'integer'}},project_names:{type:'array',items:{type:'string'}},timezone:{type:'string'},day_anchor:{type:'string',enum:['start','next_day']},force_refresh:{type:'boolean'}},required:['start_date','end_date']}},
    {name:'get_coverage',inputSchema:{type:'object',additionalProperties:false,properties:{start_date:{type:'string'},end_date:{type:'string'},project_ids:{type:'array',items:{type:'integer'}},project_names:{type:'array',items:{type:'string'}},timezone:{type:'string'},day_anchor:{type:'string',enum:['start','next_day']},force_refresh:{type:'boolean'}},required:['start_date','end_date']}},
    {name:'browse_projects_catalog',inputSchema:{type:'object',additionalProperties:false,properties:{}}},{name:'browse_tags_catalog',inputSchema:{type:'object',additionalProperties:false,properties:{}}},
    {name:'create_time_entry',inputSchema:{type:'object',additionalProperties:false,properties:{description:{type:'string'},start:{type:'string'},duration:{type:'number'},stop:{type:'string'},project_id:{type:'integer'},tags:{type:'array',items:{type:'string'}},billable:{type:'boolean'}},required:['start','duration']}},
    {name:'update_time_entry',inputSchema:{type:'object',additionalProperties:false,properties:{entry_id:{type:'integer'},description:{type:'string'},start:{type:'string'},stop:{type:'string'},duration:{type:'number'},project_id:{type:'integer'},tags:{type:'array',items:{type:'string'}},billable:{type:'boolean'}},required:['entry_id']}},
    {name:'stop_time_entry',inputSchema:{type:'object',additionalProperties:false,properties:{entry_id:{type:'integer'}},required:['entry_id']}},{name:'delete_time_entry',inputSchema:{type:'object',additionalProperties:false,properties:{entry_id:{type:'integer'}},required:['entry_id']}},
    {name:'create_project',inputSchema:{type:'object',additionalProperties:false,properties:{name:{type:'string'},color:{type:'string'},billable:{type:'boolean'},active:{type:'boolean'},client_id:{type:'integer'}},required:['name']}},{name:'update_project',inputSchema:{type:'object',additionalProperties:false,properties:{project_id:{type:'integer'},name:{type:'string'},color:{type:'string'},billable:{type:'boolean'},active:{type:'boolean'}},required:['project_id']}},{name:'delete_project',inputSchema:{type:'object',additionalProperties:false,properties:{project_id:{type:'integer'}},required:['project_id']}},
    {name:'create_tag',inputSchema:{type:'object',additionalProperties:false,properties:{name:{type:'string'}},required:['name']}},{name:'update_tag',inputSchema:{type:'object',additionalProperties:false,properties:{tag_id:{type:'integer'},name:{type:'string'}},required:['tag_id','name']}},{name:'delete_tag',inputSchema:{type:'object',additionalProperties:false,properties:{tag_id:{type:'integer'}},required:['tag_id']}}
  ];
  const ro = new Set(['get_current_time_entry','get_time_entries_with_project_tag','get_summary','get_coverage','browse_projects_catalog','browse_tags_catalog']);
  for (const x of t) { x.description = D[x.name]; x.annotations = { readOnlyHint: ro.has(x.name), destructiveHint: !ro.has(x.name) }; }
  return t;
}

function pickFields(obj, fields) { const out={}; for(const f of fields) if(obj[f]!==undefined) out[f]=obj[f]; return out; }
function timeEntryPayload(a, ws, includeCreated=true) { const out=pickFields(a,['description','start','duration','stop','project_id','tags','billable']); out.workspace_id=Number(ws); if(includeCreated)out.created_with='toggl-track-mcp'; return out; }
function projectPayload(a, ws) { const out=pickFields(a,['name','color','billable','active','client_id']); out.workspace_id=Number(ws); return out; }
async function executeTool(name, a, env, grant) {
  if (!grant) throw new Error('Not authenticated');
  const ctx = await makeCtx(env, grant);
  const ws = ctx.ws, token = ctx.token, tz = a.timezone || ctx.profileTz || 'UTC';
  const tzKnown = !!(a.timezone || ctx.profileTz);
  const tzSource = a.timezone ? 'requested' : (ctx.profileTz ? 'profile' : 'fallback_utc');

  if (name === 'get_current_time_entry') {
    ctx.prov.upstream.push('/me/time_entries/current');
    return await togglGet(token, '/me/time_entries/current');
  }

  if (name === 'get_time_entries_with_project_tag') {
    if (!a.start_date || !a.end_date) throw new Error('start_date and end_date are required');
    const dsRaw = parseDateWithTz(a.start_date, tz), deRaw = parseDateWithTz(a.end_date, tz);
    if (isNaN(dsRaw) || isNaN(deRaw)) throw new Error('invalid dates');
    if (a.day_anchor === 'next_day') { a.start_date = dayKey(dsRaw.getTime()-86400000, tz); a.end_date = dayKey(endExclusiveMs(a.end_date, deRaw)-86400000-1, tz); }
    const ds = parseDateWithTz(a.start_date, tz), de = parseDateWithTz(a.end_date, tz);
    if (isNaN(ds) || isNaN(de)) throw new Error('invalid dates');
    if (ds > de) throw new Error('start_date must be <= end_date');
    a._startMs = ds.getTime(); a._endMs = endExclusiveMs(a.end_date, de);
    normalizeBounds(a, tz);
    await ensureEntries(ctx, a, { force: !!a.force_refresh });
    await ensureProjects(ctx);
    const out = filterByDate(ctx, ctx.entries, a);
    const pgLimit = Number.isFinite(Number(a.limit)) ? Math.min(1000, Math.max(1, Number(a.limit))) : 1000;
    const pgOff = Number.isFinite(Number(a.offset)) ? Math.max(0, Math.floor(Number(a.offset))) : 0;
    const limited = out.slice(pgOff, pgOff + pgLimit);
    const pgHasMore = (pgOff + limited.length) < out.length;
    const pgFiltered = !!((a.project_ids && a.project_ids.length) || (a.project_names && a.project_names.length) || a.description_contains);
    const today = dayKey(Date.now(), tz);
    return {
      entries: limited.map(x => shapeEntry(ctx, x, a.fields, tz, tzKnown)),
      projects: Object.fromEntries([...new Set(limited.map(x=>x.project_id).filter(Boolean))].map(id => [id, ctx.projects?.[id] || {id,name:'Unknown'}])),
      meta: {
        status:'ok', requested_start:a.start_date, requested_end:a.end_date,
        returned: limited.length, total_count: out.length,
        entries_cache: ctx.prov.entries, projects_cache: ctx.prov.projects,
        upstream_calls: ctx.prov.upstream,
        completeness: ctx.incomplete ? false : ((out.length <= limited.length) ? ((a.end_date >= today) ? 'unverified' : true) : false),
        date_facts: dateFacts(out, a, tz),
        pagination: { offset: pgOff, limit: pgLimit, returned: limited.length, total_count: out.length, has_more: pgHasMore, next_offset: pgHasMore ? (pgOff + limited.length) : null, report_ready: !pgHasMore },
        truncation_hint: pgHasMore ? { reason: 'result_exceeds_page_limit', project_filter_applied: pgFiltered, recommended: pgFiltered ? 'Repeat this exact request with offset=next_offset and merge all pages before analysing.' : 'Narrow the query with project_ids/project_names first (or use get_summary); paginate with offset=next_offset only if the filtered result still exceeds the page limit.' } : undefined,
        filter_diagnostics: filterDiagnostics(ctx, a),
        cache: cacheMeta(ctx, tz), source_timezone: tz, times_are_in: tz, timezone_source: tzSource,
        warnings: tzKnown ? undefined : ['Times are rendered in UTC because no timezone argument was given and the Toggl profile timezone was unavailable. Local time fields are named utc_* instead of local_* to avoid mislabelling. Pass timezone (e.g. "Asia/Jakarta") for correct local times and day boundaries.'],
      },
    };
  }

  if (name === 'get_summary' || name === 'get_coverage') {
    if (!a.start_date || !a.end_date) throw new Error('start_date and end_date are required');
    const dsRaw2 = parseDateWithTz(a.start_date, tz), deRaw2 = parseDateWithTz(a.end_date, tz);
    if (isNaN(dsRaw2) || isNaN(deRaw2)) throw new Error('invalid dates');
    if (a.day_anchor === 'next_day') { a.start_date = dayKey(dsRaw2.getTime()-86400000, tz); a.end_date = dayKey(endExclusiveMs(a.end_date, deRaw2)-86400000-1, tz); }
    const ds = parseDateWithTz(a.start_date, tz), de = parseDateWithTz(a.end_date, tz);
    a._startMs = ds.getTime(); a._endMs = endExclusiveMs(a.end_date, de);
    normalizeBounds(a, tz);
    await ensureEntries(ctx, a, { force: !!a.force_refresh });
    const needsProjects = name==='get_summary' ? (!!(a.project_names&&a.project_names.length) || !!a.description_contains || ['project','project_day'].includes(a.group_by||'project')) : !!(a.project_names&&a.project_names.length);
    if(needsProjects) await ensureProjects(ctx); else ctx.prov.projects='not_needed';
    const rows = filterByDate(ctx, ctx.entries, a);
    const today = dayKey(Date.now(), tz);
    const commonMeta = { status:'ok', entries_cache: ctx.prov.entries, projects_cache: ctx.prov.projects, upstream_calls: ctx.prov.upstream, cache: cacheMeta(ctx, tz), filter_diagnostics: filterDiagnostics(ctx, a), source_timezone: tz, times_are_in: tz, timezone_source: tzSource, warnings: tzKnown ? undefined : ['Times are rendered in UTC because no timezone argument was given and the Toggl profile timezone was unavailable. Pass timezone (e.g. "Asia/Jakarta") for correct local times and day boundaries.'], completeness: ctx.incomplete ? false : ((a.end_date >= today) ? 'unverified' : true) };

    if (name === 'get_coverage') {
      const days = {};
      for (const x of rows) { const d = dayKey(x.start, tz); const z = days[d] || (days[d]={count:0,seconds:0}); z.count++; z.seconds += durationWithinWindow(x,a); }
      const out = []; let cursor = new Date(dayKey(new Date(a._startMs).toISOString(), tz)+'T12:00:00Z');
      const limit = new Date(dayKey(new Date(a._endMs-1).toISOString(), tz)+'T12:00:00Z');
      while (cursor <= limit) { const k = cursor.toISOString().slice(0,10); out.push({ date:k, entry_count:(days[k]||{count:0}).count, tracked_seconds:(days[k]||{seconds:0}).seconds }); cursor.setUTCDate(cursor.getUTCDate()+1); }
      const shiftC=(a.day_anchor==='next_day')?1:0;
      const outA=shiftC?out.map(x=>({...x,date:dAdd(x.date,1)})):out;
      return { days: outA, gaps: outA.filter(x=>!x.entry_count).map(x=>x.date), anomalies: rows.filter(x=>x.stop&&effDuration(x)>86400).map(x=>({entry_id:x.id,type:'duration_over_24h',duration_seconds:x.duration})), meta: commonMeta };
    }

    const g = a.group_by || 'project', m = {};
    for (const x of rows) {
      const pn = ctx.projects?.[x.project_id]?.name || 'Unknown';
      let day = dayKey(x.start, tz); if (a.day_anchor === 'next_day') day = dAdd(day,1);
      const tagKeys = Array.isArray(x.tags) && x.tags.length ? x.tags.map(t=>'tag:'+t) : ['tag:__untagged__'];
      const keys = g==='day' ? [day] : g==='tag' ? tagKeys : g==='project_day' ? [x.project_id+':'+day] : [x.project_id+':'+pn];
      for (const k of keys) {
        const z = m[k] || (m[k]={key:k,count:0,seconds:0});
        if (g==='project'||g==='project_day') { z.project_id = x.project_id||null; z.project_name = pn; }
        if (g==='day'||g==='project_day') z.date = day;
        if (g==='tag') { z.tag = k==='tag:__untagged__' ? null : k.slice(4); if(k==='tag:__untagged__') z.untagged=true; }
        z.count++; z.seconds += durationWithinWindow(x,a);
      }
    }
    return { groups: Object.values(m), meta: commonMeta };
  }

  if (name === 'browse_projects_catalog') { await ensureProjects(ctx); return Object.values(ctx.projects); }
  if (name === 'browse_tags_catalog') { await ensureTags(ctx); return ctx.tags; }

  // Writes — patch cache surgically (never nuke)
  async function invalidateEntries() { await loadEntriesCache(ctx); }
  if (name === 'create_time_entry') {
    ctx.prov.upstream.push('POST /time_entries');
    const r = await togglPost(token, '/workspaces/'+ws+'/time_entries', timeEntryPayload(a,ws));
    await patchWrite(ctx, 'create', r, null, tz); return r;
  }
  if (name === 'update_time_entry') {
    if (!a.entry_id) throw new Error('entry_id required');
    const b = timeEntryPayload(a,ws,false); delete b.workspace_id; delete b.created_with; delete b.entry_id;
    const r = await togglPut(token, '/workspaces/'+ws+'/time_entries/'+a.entry_id, b);
    await patchWrite(ctx, 'update', r, Number(a.entry_id), tz); return r;
  }
  if (name === 'stop_time_entry') {
    if (!a.entry_id) throw new Error('entry_id required');
    const r = await togglPatch(token, '/workspaces/'+ws+'/time_entries/'+a.entry_id+'/stop');
    await patchWrite(ctx, 'update', r, Number(a.entry_id), tz); return r;
  }
  if (name === 'delete_time_entry') {
    if (!a.entry_id) throw new Error('entry_id required');
    const r = await togglDelete(token, '/workspaces/'+ws+'/time_entries/'+a.entry_id);
    await patchWrite(ctx, 'delete', null, Number(a.entry_id), tz); return { ok: true };
  }
  if (name === 'create_project') { const r = await togglPost(token, '/workspaces/'+ws+'/projects', projectPayload(a,ws)); await kvDel(env, ctx.kProjects); return r; }
  if (name === 'update_project') { if(!a.project_id) throw new Error('project_id required'); const b=projectPayload(a,ws); delete b.project_id; delete b.workspace_id; const r = await togglPut(token, '/workspaces/'+ws+'/projects/'+a.project_id, b); await kvDel(env, ctx.kProjects); return r; }
  if (name === 'delete_project') { if(!a.project_id) throw new Error('project_id required'); const r = await togglDelete(token, '/workspaces/'+ws+'/projects/'+a.project_id); await kvDel(env, ctx.kProjects); return { ok:true }; }
  if (name === 'create_tag') { const r = await togglPost(token, '/workspaces/'+ws+'/tags', { name:a.name, workspace_id:Number(ws) }); await kvDel(env, ctx.kTags); return r; }
  if (name === 'update_tag') { if(!a.tag_id) throw new Error('tag_id required'); const r = await togglPut(token, '/workspaces/'+ws+'/tags/'+a.tag_id, { name:a.name }); await kvDel(env, ctx.kTags); return r; }
  if (name === 'delete_tag') { if(!a.tag_id) throw new Error('tag_id required'); const r = await togglDelete(token, '/workspaces/'+ws+'/tags/'+a.tag_id); await kvDel(env, ctx.kTags); return { ok:true }; }

  throw new Error('Unknown tool: ' + name);
}

async function patchWrite(ctx, op, entry, id, tz) {
  await loadEntriesCache(ctx);
  if (!ctx.entries.length && !(ctx.ranges||[]).length) return;
  if (op === 'delete' && id != null) ctx.entries = ctx.entries.filter(x => x.id !== id);
  else if (entry && entry.id != null) ctx.entries = mergeEntries(ctx.entries, [entry]);
  ctx.entries = mergeEntries([], ctx.entries);
  await saveEntriesCache(ctx);
}
async function togglPost(token, path, body) { return togglWrite(token, 'POST', path, body); }
async function togglPut(token, path, body) { return togglWrite(token, 'PUT', path, body); }
async function togglPatch(token, path) { return togglWrite(token, 'PATCH', path, null); }
async function togglDelete(token, path) { return togglWrite(token, 'DELETE', path, null); }
async function togglWrite(token, method, path, body) {
  const r = await fetch(TOGGL_BASE + path, { method, headers: { Authorization: togglAuthHeader(token), 'Content-Type':'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let d; try { d = JSON.parse(t); } catch { d = t; }
  if (!r.ok) throw new Error('Toggl ' + r.status);
  return d;
}

const MCP_PROTOCOLS = [MCP_PROTOCOL];
const TOOL_KEYS = {
  get_current_time_entry: [],
  get_time_entries_with_project_tag: ['start_date','end_date','project_ids','project_names','description_contains','min_duration_seconds','intersects_range','fields','limit','offset','timezone','day_anchor','force_refresh'],
  get_summary: ['start_date','end_date','group_by','project_ids','project_names','timezone','day_anchor','force_refresh'],
  get_coverage: ['start_date','end_date','project_ids','project_names','timezone','day_anchor','force_refresh'],
  browse_projects_catalog: [], browse_tags_catalog: [],
  create_time_entry: ['description','start','duration','stop','project_id','tags','billable'],
  update_time_entry: ['entry_id','description','start','duration','stop','project_id','tags','billable'],
  stop_time_entry: ['entry_id'], delete_time_entry: ['entry_id'],
  create_project: ['name','color','billable','active','client_id'], update_project: ['project_id','name','color','billable','active'], delete_project: ['project_id'],
  create_tag: ['name'], update_tag: ['tag_id','name'], delete_tag: ['tag_id'],
};
const VALID_SHAPE_FIELDS = new Set(['id','start','stop','duration','description','project_id','tags','billable','workspace_id','user_id','task_id','at','created_with','project_name','project.name','local_start_date','local_start_time','local_stop_date','local_stop_time']);
function requireInteger(v,name,min=0,max=Number.MAX_SAFE_INTEGER){if(typeof v!=='number'||!Number.isInteger(v)||v<min||v>max)throw new Error(name+' must be an integer between '+min+' and '+max);}
function validateToolArgs(name,a){
  if(!a||typeof a!=='object'||Array.isArray(a))throw new Error('Tool arguments must be an object');
  const allowed=TOOL_KEYS[name]; if(!allowed)throw new Error('Unknown tool: '+name);
  for(const k of Object.keys(a))if(!allowed.includes(k))throw new Error('Unknown argument: '+k);
  const needs=['get_time_entries_with_project_tag','get_summary','get_coverage']; if(needs.includes(name)){if(typeof a.start_date!=='string'||typeof a.end_date!=='string'||!a.start_date||!a.end_date)throw new Error('start_date and end_date are required');}
  if(name==='get_summary'&&a.group_by!==undefined&&!['project','day','tag','project_day'].includes(a.group_by))throw new Error('group_by must be project, day, tag, or project_day');
  if(a.day_anchor!==undefined&&!['start','next_day'].includes(a.day_anchor))throw new Error('day_anchor must be start or next_day');
  if(a.limit!==undefined)requireInteger(a.limit,'limit',1,1000); if(a.offset!==undefined)requireInteger(a.offset,'offset',0);
  if(a.project_ids!==undefined){if(!Array.isArray(a.project_ids)||a.project_ids.some(x=>typeof x!=='number'||!Number.isInteger(x)))throw new Error('project_ids must be an integer array');}
  if(a.project_names!==undefined&&(!Array.isArray(a.project_names)||a.project_names.some(x=>typeof x!=='string')))throw new Error('project_names must be a string array');
  if(a.fields!==undefined&&(!Array.isArray(a.fields)||a.fields.some(x=>typeof x!=='string'||!VALID_SHAPE_FIELDS.has(x))))throw new Error('fields contains an unsupported field');
  for(const k of ['force_refresh','intersects_range','billable','active'])if(a[k]!==undefined&&typeof a[k]!=='boolean')throw new Error(k+' must be boolean');
  if(a.min_duration_seconds!==undefined&&(typeof a.min_duration_seconds!=='number'||!Number.isFinite(a.min_duration_seconds)||a.min_duration_seconds<0))throw new Error('min_duration_seconds must be a non-negative number');
  if(name==='create_time_entry'&& (typeof a.start!=='string'||typeof a.duration!=='number'))throw new Error('create_time_entry requires start and duration');
  if(['update_time_entry','stop_time_entry','delete_time_entry'].includes(name)&&(!Number.isInteger(a.entry_id)||a.entry_id<=0))throw new Error('entry_id must be a positive integer');
  if(name==='update_time_entry'&&!Object.keys(a).some(k=>k!=='entry_id'))throw new Error('update_time_entry requires a mutable field');
  if(['create_project','create_tag'].includes(name)&&typeof a.name!=='string'&&! (name==='create_project'&&typeof a.name==='string'))throw new Error(name+' requires name');
  if(name==='create_project'&&(!a.name||typeof a.name!=='string'))throw new Error('create_project requires name');
  if(name==='create_tag'&&(!a.name||typeof a.name!=='string'))throw new Error('create_tag requires name');
  if(['update_project','delete_project'].includes(name)&&(!Number.isInteger(a.project_id)||a.project_id<=0))throw new Error('project_id must be a positive integer');
  if(name==='update_project'&&!Object.keys(a).some(k=>k!=='project_id'))throw new Error('update_project requires a mutable field');
  if(['update_tag','delete_tag'].includes(name)&&(!Number.isInteger(a.tag_id)||a.tag_id<=0))throw new Error('tag_id must be a positive integer');
  if(name==='update_tag'&&(!a.name||typeof a.name!=='string'))throw new Error('update_tag requires name');
  if(a.timezone!==undefined){try{new Intl.DateTimeFormat('en-US',{timeZone:a.timezone}).format();}catch{throw new Error('Invalid IANA timezone');}}
  return a;
}

// ─── MCP handler ─────────────────────────────────────────────────────────────
async function handleMCP(request, env, grant) {
  if(request.method!=='POST')return json({error:'Method not allowed'},405,{'Allow':'POST'});
  const hdr=request.headers.get('MCP-Protocol-Version'); if(hdr&&!MCP_PROTOCOLS.includes(hdr))return jsonError('unsupported_protocol_version','Unsupported MCP-Protocol-Version',400);
  let body; try{body=await request.json();}catch{return json({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}},400);}
  const id=body.id??null, method=body.method;
  if(method==='initialize'){
    const requested=body.params?.protocolVersion||MCP_PROTOCOL; const negotiated=MCP_PROTOCOLS.includes(requested)?requested:MCP_PROTOCOL;
    return json({jsonrpc:'2.0',id,result:{protocolVersion:negotiated,capabilities:{tools:{}},serverInfo:{name:'toggl-track-mcp',version:'1.1.0'},instructions:'Read-first, cache-first Toggl time tracking for YOUR connected account. The primary read tool is get_time_entries_with_project_tag with a 1000-entry page cap. If report_ready is false, continue with offset or narrow the filter before reporting. Use get_summary or get_coverage for aggregates. Do not call catalogs for normal reporting. end_date is inclusive and end_date+1 is used internally for Toggl v9. Provide timezone for local boundaries. force_refresh costs Toggl quota and is only for explicit user refresh requests.'}});
  }
  if(method==='notifications/initialized')return new Response(null,{status:202,headers:CORS});
  if(method==='ping')return json({jsonrpc:'2.0',id,result:{}});
  if(method==='tools/list')return json({jsonrpc:'2.0',id,result:{tools:toolsList()}});
  if(method==='tools/call'){
    const name=body.params?.name,args=body.params?.arguments||{};
    try{validateToolArgs(name,args);const result=await executeTool(name,{...args},env,grant);return json({jsonrpc:'2.0',id,result:{content:[{type:'text',text:typeof result==='string'?result:JSON.stringify(result)}]}});}catch(e){return json({jsonrpc:'2.0',id,result:{content:[{type:'text',text:e.message||String(e)}],isError:true}});}
  }
  return json({jsonrpc:'2.0',id,error:{code:-32601,message:'Method not found: '+method}});
}

// ─── Dispatcher ──────────────────────────────────────────────────────────────
export class OAuthStateDO {
  constructor(state, env) { this.state=state; this.env=env; }
  async fetch(request) {
    let body={}; try{body=await request.json();}catch{return new Response(JSON.stringify({ok:false,error:'invalid_state_request'}),{status:400,headers:{'content-type':'application/json'}});}
    const now=Date.now(), current=await this.state.storage.get('record');
    if(current&&current.expires_at&&current.expires_at<now){await this.state.storage.delete('record');}
    const live=current&&(!current.expires_at||current.expires_at>=now)?current:null;
    if(body.op==='create'){
      if(live)return new Response(JSON.stringify({ok:false,error:'state_exists'}),{status:409,headers:{'content-type':'application/json'}});
      const ttl=Number(body.ttl)||CODE_TTL; await this.state.storage.put('record',{record:body.record,expires_at:now+ttl*1000}); return new Response(JSON.stringify({ok:true,value:true}),{headers:{'content-type':'application/json'}});
    }
    if(body.op==='get')return new Response(JSON.stringify({ok:true,value:live?live.record:null}),{headers:{'content-type':'application/json'}});
    if(body.op==='consume'){
      if(!live)return new Response(JSON.stringify({ok:true,value:null}),{headers:{'content-type':'application/json'}});
      await this.state.storage.delete('record'); return new Response(JSON.stringify({ok:true,value:live.record}),{headers:{'content-type':'application/json'}});
    }
    if(body.op==='revoke'){await this.state.storage.delete('record');return new Response(JSON.stringify({ok:true,value:true}),{headers:{'content-type':'application/json'}});}
    return new Response(JSON.stringify({ok:false,error:'unknown_state_operation'}),{status:400,headers:{'content-type':'application/json'}});
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
    try {
      const oauthResult = await handleOAuth(request, env, url);
      if (oauthResult) return oauthResult;
      if (path === '/api/validate-toggl' && request.method === 'POST') return handleValidateToggl(request, env);
      if (path === '/mcp' || (path === '/' && request.method === 'POST')) {
        const grant = await authenticate(request, env);
        if (!grant) return new Response('Unauthorized', { status: 401, headers: { ...CORS, 'WWW-Authenticate': 'Bearer resource_metadata="' + env.BASE_URL + '/.well-known/oauth-protected-resource"' } });
        return handleMCP(request, env, grant);
      }
      if (path === '/' || path === '/healthz') return json({ ok: true, server: 'toggl-track-mcp', version: '1.1.0', tools: toolsList().length });
      return new Response('Not found', { status: 404, headers: CORS });
    } catch (e) {
      return json({ error: e.message || 'Internal error' }, 500);
    }
  },
};
