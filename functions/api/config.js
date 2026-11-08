// Indique au site quelles IA sont configurées. Ne révèle jamais les clés elles-mêmes.
export async function onRequestGet(context) {
  const env = context.env;
  const providers = [];
  if (env.GEMINI_API_KEY) providers.push("gemini");
  if (env.GROQ_API_KEY) providers.push("groq");
  if (env.MISTRAL_API_KEY) providers.push("mistral");
  return new Response(JSON.stringify({ providers: providers }), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
