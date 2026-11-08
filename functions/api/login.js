// Connexion : Google, GitHub ou Microsoft. Crée une session signée valable 30 jours.
const DUREE = 30 * 24 * 3600; // en secondes

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status,
    headers: { "Content-Type": "application/json" },
  });
}

function erreur(message, status) {
  return json({ error: { message: message } }, status);
}

function enBase64Url(octets) {
  let bin = "";
  for (let i = 0; i < octets.length; i++) bin += String.fromCharCode(octets[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function enOctets(b64url) {
  let s = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}

function lireJeton(b64url) {
  return JSON.parse(new TextDecoder().decode(enOctets(b64url)));
}

async function signer(texte, secret) {
  const cle = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cle, new TextEncoder().encode(texte));
  return enBase64Url(new Uint8Array(sig));
}

const FOURNISSEURS = {
  google: { nom: "Google", vars: ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"] },
  github: { nom: "GitHub", vars: ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"] },
  microsoft: { nom: "Microsoft", vars: ["MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"] },
};

// Google : code échangé en mode popup (redirect_uri = "postmessage")
async function profilGoogle(code, env) {
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code: code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: "postmessage",
      grant_type: "authorization_code",
    }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.id_token) return null;
  const infos = lireJeton(d.id_token.split(".")[1]);
  const emetteurOk = infos.iss === "https://accounts.google.com" || infos.iss === "accounts.google.com";
  if (infos.aud !== env.GOOGLE_CLIENT_ID || !emetteurOk || !infos.sub) return null;
  return { sub: String(infos.sub), name: infos.name, given_name: infos.given_name, picture: infos.picture };
}

// GitHub : échange du code, puis lecture du profil
async function profilGitHub(code, redirect, env) {
  const r = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code: code,
      redirect_uri:
