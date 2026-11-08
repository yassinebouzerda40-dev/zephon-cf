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
      redirect_uri: redirect,
    }),
  });
  const t = await r.json().catch(() => ({}));
  if (!t.access_token) return null;
  const u = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: "Bearer " + t.access_token,
      Accept: "application/vnd.github+json",
      "User-Agent": "ZEPHON",
    },
  });
  const d = await u.json().catch(() => ({}));
  if (!d.id) return null;
  const nom = d.name || d.login || "";
  return {
    sub: "github:" + d.id,
    name: nom,
    given_name: nom.split(" ")[0],
    picture: d.avatar_url,
  };
}

// Microsoft : échange du code, le jeton d'identité vient directement de Microsoft
async function profilMicrosoft(code, redirect, env) {
  const r = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.MICROSOFT_CLIENT_ID,
      client_secret: env.MICROSOFT_CLIENT_SECRET,
      code: code,
      redirect_uri: redirect,
      grant_type: "authorization_code",
      scope: "openid profile email",
    }),
  });
  const t = await r.json().catch(() => ({}));
  if (!t.id_token) return null;
  const infos = lireJeton(t.id_token.split(".")[1]);
  if (infos.aud !== env.MICROSOFT_CLIENT_ID || !infos.sub || !infos.exp || infos.exp * 1000 < Date.now()) return null;
  const nom = infos.name || infos.preferred_username || "";
  return {
    sub: "microsoft:" + infos.sub,
    name: nom,
    given_name: infos.given_name || nom.split(" ")[0],
    picture: "",
  };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // Refuse les appels qui ne viennent pas de ton propre site
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) {
    return erreur("Origine refusée", 403);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return erreur("Requête invalide", 400);
  }
  if (!body.code || typeof body.code !== "string") return erreur("Requête invalide", 400);

  const id = body.provider || "google";
  const fournisseur = FOURNISSEURS[id];
  if (!fournisseur) return erreur("Fournisseur inconnu", 400);
  if (fournisseur.vars.some(function (v) { return !env[v]; })) {
    return erreur("La connexion " + fournisseur.nom + " n'est pas encore configurée sur le serveur", 500);
  }
  if (!env.SESSION_SECRET) return erreur("SESSION_SECRET manquant sur le serveur", 500);

  const redirect = new URL(request.url).origin + "/";
  let profil = null;
  try {
    if (id === "github") profil = await profilGitHub(body.code, redirect, env);
    else if (id === "microsoft") profil = await profilMicrosoft(body.code, redirect, env);
    else profil = await profilGoogle(body.code, env);
  } catch (e) {
    return erreur("Impossible de joindre " + fournisseur.nom, 502);
  }
  if (!profil) return erreur("Connexion refusée par " + fournisseur.nom, 401);

  const propre = {
    sub: String(profil.sub).slice(0, 80),
    name: String(profil.name || "").slice(0, 80),
    given_name: String(profil.given_name || "").slice(0, 40),
    picture: /^https:\/\//.test(profil.picture || "") ? profil.picture : "",
  };
  const payload = Object.assign({}, propre, { exp: Math.floor(Date.now() / 1000) + DUREE });
  const p = enBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const session = p + "." + (await signer(p, env.SESSION_SECRET));
  return json({ session: session, profile: propre }, 200);
}
