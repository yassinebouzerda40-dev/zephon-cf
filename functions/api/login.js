// Connexion avec Google : échange le code reçu contre l'identité de la personne,
// puis crée une session signée, valable 30 jours.
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

async function signer(texte, secret) {
  const cle = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cle, new TextEncoder().encode(texte));
  return enBase64Url(new Uint8Array(sig));
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // Refuse les appels qui ne viennent pas de ton propre site
  const origin = request.headers.get("Origin");
  if (origin && origin !== new URL(request.url).origin) {
    return erreur("Origine refusée", 403);
  }

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.SESSION_SECRET) {
    return erreur("La connexion Google n'est pas encore configurée sur le serveur", 500);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return erreur("Requête invalide", 400);
  }
  if (!body.code || typeof body.code !== "string") return erreur("Requête invalide", 400);

  // On donne le code à Google, qui répond avec l'identité de la personne
  let r;
  try {
    r = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: body.code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: "postmessage",
        grant_type: "authorization_code",
      }),
    });
  } catch (e) {
    return erreur("Impossible de joindre Google", 502);
  }
  let d = {};
  try {
    d = await r.json();
  } catch (e) {}
  if (!r.ok || !d.id_token) return erreur("Connexion refusée par Google", 401);

  // Le jeton vient directement de Google (connexion sécurisée) : on vérifie quand même à qui il s'adresse
  let infos;
  try {
    infos = JSON.parse(new TextDecoder().decode(enOctets(d.id_token.split(".")[1])));
  } catch (e) {
    return erreur("Réponse de Google invalide", 502);
  }
  const emetteurOk = infos.iss === "https://accounts.google.com" || infos.iss === "accounts.google.com";
  if (infos.aud !== env.GOOGLE_CLIENT_ID || !emetteurOk || !infos.sub) {
    return erreur("Connexion refusée", 401);
  }

  const profil = {
    sub: String(infos.sub),
    name: String(infos.name || "").slice(0, 80),
    given_name: String(infos.given_name || "").slice(0, 40),
    picture: /^https:\/\//.test(infos.picture || "") ? infos.picture : "",
  };
  const payload = Object.assign({}, profil, { exp: Math.floor(Date.now() / 1000) + DUREE });
  const p = enBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const session = p + "." + (await signer(p, env.SESSION_SECRET));
  return json({ session: session, profile: profil }, 200);
}
