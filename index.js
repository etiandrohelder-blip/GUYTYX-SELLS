/**
 * GUYTIX SELLS — Servidor de licenciamento (Cloudflare Workers)
 * Não precisa de cartão de crédito. Guarda o segredo da fórmula de
 * renovação e fala com o Firestore usando uma Service Account do
 * Google (que também não precisa de cartão — isso é só para o
 * Firestore em si, que já é grátis no plano Spark).
 */

const MONTHLY_FEE = 12000;

export default {
  async fetch(request, env) {
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    const url = new URL(request.url);
    try {
      if (url.pathname === "/renewSubscription" && request.method === "POST") {
        return await handleRenew(request, env, cors);
      }
      if (url.pathname === "/generateRenewCode" && request.method === "POST") {
        return await handleGenerate(request, env, cors);
      }
      return json({ error: "Rota não encontrada" }, 404, cors);
    } catch (e) {
      return json({ error: e.message || "Erro interno" }, 500, cors);
    }
  },
};

/* ================= ROTA PÚBLICA: renovar assinatura ================= */
async function handleRenew(request, env, cors) {
  const body = await request.json().catch(() => ({}));
  const { bizId, code } = body;
  if (!bizId || !code) return json({ error: "Dados incompletos" }, 400, cors);

  const authHeader = request.headers.get("Authorization") || "";
  const idToken = authHeader.replace(/^Bearer\s+/i, "");
  if (!idToken) return json({ error: "Login necessário" }, 401, cors);

  let payload;
  try {
    payload = await verifyFirebaseIdToken(idToken, env.GCP_PROJECT_ID);
  } catch (e) {
    return json({ error: "Sessão inválida: " + e.message }, 401, cors);
  }
  const uid = payload.user_id || payload.sub;

  const biz = await getDoc(env, "businesses/" + bizId);
  if (!biz) return json({ error: "Negócio não encontrado" }, 404, cors);
  const membersMap = biz.membersMap || {};
  if (!membersMap[uid]) return json({ error: "Sem acesso a este negócio" }, 403, cors);

  const now = Date.now();
  const WINDOW = 60 * 60 * 1000;
  const MAX_TRIES = 8;
  let count = biz.renewAttempts || 0;
  let windowStart = biz.renewWindowStart || 0;
  if (now - windowStart > WINDOW) { count = 0; windowStart = now; }
  if (count >= MAX_TRIES) return json({ error: "Muitas tentativas. Aguarde 1 hora." }, 429, cors);

  const valid = calcRenewCode(biz.adminPhone, currentYYYYMM(), env.GUYTIX_SALT);
  if (code !== valid) {
    await patchDoc(env, "businesses/" + bizId, { renewAttempts: count + 1, renewWindowStart: windowStart });
    return json({ error: "Código inválido" }, 400, cors);
  }

  const newExpiry = new Date();
  newExpiry.setDate(newExpiry.getDate() + 30);
  const expiryStr = newExpiry.toISOString().slice(0, 10);
  await patchDoc(env, "businesses/" + bizId, { expiry: expiryStr, renewAttempts: 0, renewWindowStart: 0 });
  return json({ ok: true, expiry: expiryStr }, 200, cors);
}

/* ================= ROTA PRIVADA: gerar código (só o painel privado chama) ================= */
async function handleGenerate(request, env, cors) {
  const body = await request.json().catch(() => ({}));
  const { phone, masterPass } = body;
  if (!phone || !masterPass) return json({ error: "Dados incompletos" }, 400, cors);

  const now = Date.now();
  const rl = (await env.GUYTIX_KV.get("rl_generate", "json")) || { count: 0, windowStart: now };
  if (now - rl.windowStart > 15 * 60 * 1000) { rl.count = 0; rl.windowStart = now; }
  if (rl.count >= 5) return json({ error: "Muitas tentativas erradas. Aguarde 15 minutos." }, 429, cors);

  const hashHex = await sha256Hex(masterPass);
  if (hashHex !== env.GUYTIX_MASTER_HASH) {
    rl.count += 1;
    await env.GUYTIX_KV.put("rl_generate", JSON.stringify(rl));
    return json({ error: "Senha mestre incorreta" }, 403, cors);
  }
  await env.GUYTIX_KV.put("rl_generate", JSON.stringify({ count: 0, windowStart: now }));

  const code = calcRenewCode(phone.replace(/\D/g, ""), currentYYYYMM(), env.GUYTIX_SALT);
  return json({ code }, 200, cors);
}

/* ================= FÓRMULA (o segredo em si) ================= */
function calcRenewCode(phone, yyyymm, salt) {
  const s = phone + "|" + yyyymm + "|GUYTIXSELLS|" + MONTHLY_FEE + "|" + salt;
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) >>> 0; }
  return String(100000 + (h % 900000));
}
function currentYYYYMM() {
  const d = new Date();
  return d.getFullYear() + String(d.getMonth() + 1).padStart(2, "0");
}
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ================= VERIFICAÇÃO DO LOGIN (Firebase ID token) ================= */
async function verifyFirebaseIdToken(idToken, projectId) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("token malformado");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(b64urlToStr(headerB64));
  const payload = JSON.parse(b64urlToStr(payloadB64));
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId) throw new Error("audience inválida");
  if (payload.iss !== "https://securetoken.google.com/" + projectId) throw new Error("issuer inválido");
  if (payload.exp < now) throw new Error("token expirado");
  if (payload.iat > now + 60) throw new Error("token com data futura");

  const jwks = await fetch(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
  ).then((r) => r.json());
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("chave de assinatura desconhecida");

  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const data = new TextEncoder().encode(headerB64 + "." + payloadB64);
  const sig = b64urlToBuf(sigB64);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, data);
  if (!ok) throw new Error("assinatura do token inválida");
  return payload;
}

/* ================= ACESSO AO FIRESTORE (via Service Account, sem cartão) ================= */
let cachedToken = null;
let cachedTokenExpiry = 0;

async function getGoogleAccessToken(env) {
  if (cachedToken && Date.now() < cachedTokenExpiry - 60000) return cachedToken;

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: env.GCP_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const headerB64 = strToB64url(JSON.stringify(header));
  const claimB64 = strToB64url(JSON.stringify(claim));
  const toSign = headerB64 + "." + claimB64;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(env.GCP_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(toSign));
  const jwt = toSign + "." + bufToB64url(sig);

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body:
      "grant_type=" +
      encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") +
      "&assertion=" +
      jwt,
  });
  const data = await res.json();
  if (!data.access_token) throw new Error("Falha ao autenticar com a Google: " + (data.error_description || JSON.stringify(data)));
  cachedToken = data.access_token;
  cachedTokenExpiry = Date.now() + data.expires_in * 1000;
  return cachedToken;
}

function firestoreBase(projectId) {
  return `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;
}

async function getDoc(env, path) {
  const token = await getGoogleAccessToken(env);
  const res = await fetch(`${firestoreBase(env.GCP_PROJECT_ID)}/${path}`, {
    headers: { Authorization: "Bearer " + token },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Erro ao ler documento: " + res.status);
  const doc = await res.json();
  return parseFirestoreFields(doc.fields || {});
}

async function patchDoc(env, path, updates) {
  const token = await getGoogleAccessToken(env);
  const mask = Object.keys(updates)
    .map((k) => "updateMask.fieldPaths=" + encodeURIComponent(k))
    .join("&");
  const res = await fetch(`${firestoreBase(env.GCP_PROJECT_ID)}/${path}?${mask}`, {
    method: "PATCH",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: toFirestoreFields(updates) }),
  });
  if (!res.ok) throw new Error("Erro ao atualizar documento: " + res.status + " " + (await res.text()));
  return res.json();
}

function parseFirestoreFields(fields) {
  const out = {};
  for (const k in fields) out[k] = parseFirestoreValue(fields[k]);
  return out;
}
function parseFirestoreValue(v) {
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.integerValue !== undefined) return parseInt(v.integerValue, 10);
  if (v.doubleValue !== undefined) return v.doubleValue;
  if (v.booleanValue !== undefined) return v.booleanValue;
  if (v.mapValue !== undefined) return parseFirestoreFields(v.mapValue.fields || {});
  if (v.nullValue !== undefined) return null;
  return null;
}
function toFirestoreFields(obj) {
  const out = {};
  for (const k in obj) out[k] = toFirestoreValue(obj[k]);
  return out;
}
function toFirestoreValue(v) {
  if (typeof v === "string") return { stringValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === "boolean") return { booleanValue: v };
  if (v === null) return { nullValue: null };
  throw new Error("tipo não suportado: " + typeof v);
}

/* ================= HELPERS DE CODIFICAÇÃO ================= */
function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...headers } });
}
function strToB64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function bufToB64url(buf) {
  let bin = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBuf(b64url) {
  const pad = b64url.length % 4 === 0 ? "" : "=".repeat(4 - (b64url.length % 4));
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function b64urlToStr(b64url) {
  return new TextDecoder().decode(b64urlToBuf(b64url));
}
function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
