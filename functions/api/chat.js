// Fonction serveur : les clés restent ici, jamais visibles par les visiteurs.
const SYSTEM =
  "Tu es ZEPHON, une IA polyvalente. Tu t'adaptes au style de l'utilisateur (tutoiement ou vouvoiement, argot, emojis). Tu reponds de facon claire et directe. Pour le code, donne le code complet puis une courte explication.";

// Noms des modèles : modifie-les ici si un fournisseur en retire un.
const GEMINI_MODEL = "gemini-3.8-flash";
const IA = {
  gemini: { cle: "GEMINI_API_KEY" },
  groq: {
    cle: "GROQ_API_KEY",
    url: "https://api.groq.com/openai/v1/chat/completions",
    model: "llama-3.3-70b-versatile",
  },
  mistral: {
    cle: "MISTRAL_API_KEY",
    url: "https://api.mistral.ai/v1/chat/completions",
    model: "mistral-small-latest",
  },
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status,
    headers: { "Content-Type": "application/json" },
  });
}

function erreur(message, status) {
  return json({ error: { message: message } }, status);
}


// ---- Vérification de la session (créée par login.js) ----
function enOctets(b64url) {
  let s = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}

async function verifierSession(jeton, secret) {
  try {
    const parts = String(jeton || "").split(".");
    if (parts.length !== 2) return null;
    const cle = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const ok = await crypto.subtle.verify(
      "HMAC", cle, enOctets(parts[1]), new TextEncoder().encode(parts[0])
    );
    if (!ok) return null;
    const infos = JSON.parse(new TextDecoder().decode(enOctets(parts[0])));
    if (!infos.exp || infos.exp * 1000 < Date.now()) return null;
    return infos;
  } catch (e) {
    return null;
  }
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

  // Si GOOGLE_CLIENT_ID est configuré, seuls les gens connectés avec Google peuvent discuter
  if (env.GOOGLE_CLIENT_ID) {
    if (!env.SESSION_SECRET) return erreur("Configuration incomplète : SESSION_SECRET manquant", 500);
    const profil = await verifierSession(body.session, env.SESSION_SECRET);
    if (!profil) return erreur("Connexion requise", 401);
  }

  const cfg = IA[body.provider];
  if (!cfg) return erreur("IA inconnue", 400);

  const cle = env[cfg.cle];
  if (!cle) return erreur("Cette IA n'est pas encore configurée sur le serveur", 400);

  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    return erreur("Requête invalide", 400);
  }
  const messages = body.messages
    .slice(-30) // garde les 30 derniers messages
    .filter(function (m) {
      return m && (m.role === "user" || m.role === "assistant") && typeof m.content === "string";
    });
  if (messages.length === 0 || JSON.stringify(messages).length > 30000) {
    return erreur("Conversation invalide ou trop longue", 413);
  }

  try {
    let r;
    if (body.provider === "gemini") {
      r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/" + GEMINI_MODEL + ":generateContent",
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-goog-api-key": cle },
          body: JSON.stringify({
            system_instruction: { parts: [{ text: SYSTEM }] },
            contents: messages.map(function (m) {
              return {
                role: m.role === "assistant" ? "model" : "user",
                parts: [{ text: m.content }],
              };
            }),
          }),
        }
      );
    } else {
      r = await fetch(cfg.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + cle },
        body: JSON.stringify({
          model: cfg.model,
          messages: [{ role: "system", content: SYSTEM }].concat(messages),
        }),
      });
    }

    let d = {};
    try {
      d = await r.json();
    } catch (e) {}

    if (!r.ok) {
      const msg = (d.error && d.error.message) || d.message || "Erreur du fournisseur";
      return erreur(String(msg), r.status);
    }

    let texte = "";
    if (body.provider === "gemini") {
      const parts = (d.candidates && d.candidates[0] && d.candidates[0].content.parts) || [];
      texte = parts.map(function (p) { return p.text || ""; }).join("");
    } else {
      texte = (d.choices && d.choices[0] && d.choices[0].message && d.choices[0].message.content) || "";
    }
    return json({ text: texte || "(pas de réponse)" }, 200);
  } catch (e) {
    return erreur("Impossible de joindre l'IA", 502);
  }
}
