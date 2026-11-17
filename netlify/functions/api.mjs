// Glitch-Hub Server: Konten (Name + Passwort) und Likes/Dislikes
// Speichert alles in Netlify Blobs (kostenlos, ohne extra Einrichtung).
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// Muss zu den Spiel-IDs in public/index.html passen
const GAMES = new Set([
  "neon-bay", "polytrack", "football-manager", "wheelie-bike", "schach", "blockblast",
  "lava-rise", "pizza-merk", "subway-surfers", "steal-an-egg", "case-opening",
  "cookie-clicker", "auktionlive", "ggamble",
]);

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");
const key = (name) => name.toLowerCase();
const NAME_RE = /^[A-Za-z0-9_\-äöüÄÖÜß]{3,16}$/;

async function session(store, req) {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const s = await store.get(`sessions/${token}`, { type: "json" });
  return s ? { token, ...s } : null;
}

async function newSession(store, user) {
  const token = crypto.randomBytes(32).toString("hex");
  await store.setJSON(`sessions/${token}`, { user: key(user.name), name: user.name, t: Date.now() });
  return token;
}

const counts = (v) => {
  let up = 0, down = 0;
  for (const x of Object.values(v || {})) { if (x === 1) up++; else if (x === -1) down++; }
  return { up, down };
};

export default async (req) => {
  const store = getStore({ name: "glitch-hub", consistency: "strong" });
  const path = new URL(req.url).pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  let body = {};
  if (req.method === "POST") { try { body = await req.json(); } catch { body = {}; } }

  try {
    // Alle Likes/Dislikes (+ eigene Stimmen, wenn angemeldet)
    if (path === "votes" && req.method === "GET") {
      const s = await session(store, req);
      const ids = [...GAMES];
      const all = await Promise.all(ids.map((id) => store.get(`votes/${id}`, { type: "json" })));
      const out = {}, mine = {};
      ids.forEach((id, i) => {
        out[id] = counts(all[i]);
        if (s && all[i] && all[i][s.user]) mine[id] = all[i][s.user];
      });
      return json({ counts: out, mine, user: s ? s.name : null });
    }

    // Registrieren
    if (path === "register" && req.method === "POST") {
      const name = String(body.name || "").trim(), pw = String(body.password || "");
      if (!NAME_RE.test(name)) return json({ error: "Name: 3–16 Zeichen, nur Buchstaben, Zahlen, _ und -" }, 400);
      if (pw.length < 4) return json({ error: "Passwort muss mindestens 4 Zeichen haben" }, 400);
      if (await store.get(`users/${key(name)}`)) return json({ error: "Diesen Namen gibt es schon" }, 409);
      const salt = crypto.randomBytes(16).toString("hex");
      const user = { name, salt, hash: hash(pw, salt), created: Date.now() };
      await store.setJSON(`users/${key(name)}`, user);
      return json({ token: await newSession(store, user), name });
    }

    // Anmelden
    if (path === "login" && req.method === "POST") {
      const name = String(body.name || "").trim(), pw = String(body.password || "");
      const user = NAME_RE.test(name) ? await store.get(`users/${key(name)}`, { type: "json" }) : null;
      const ok = user && crypto.timingSafeEqual(Buffer.from(hash(pw, user.salt), "hex"), Buffer.from(user.hash, "hex"));
      if (!ok) return json({ error: "Name oder Passwort falsch" }, 401);
      return json({ token: await newSession(store, user), name: user.name });
    }

    // Abmelden
    if (path === "logout" && req.method === "POST") {
      const s = await session(store, req);
      if (s) await store.delete(`sessions/${s.token}`);
      return json({ ok: true });
    }

    // Liken / Disliken (v: 1 = Like, -1 = Dislike, 0 = zurücknehmen)
    if (path === "vote" && req.method === "POST") {
      const s = await session(store, req);
      if (!s) return json({ error: "Bitte anmelden" }, 401);
      const game = String(body.game || ""), v = Number(body.v);
      if (!GAMES.has(game) || ![1, -1, 0].includes(v)) return json({ error: "Ungültig" }, 400);
      const votes = (await store.get(`votes/${game}`, { type: "json" })) || {};
      if (v === 0) delete votes[s.user]; else votes[s.user] = v;
      await store.setJSON(`votes/${game}`, votes);
      return json({ counts: counts(votes), mine: votes[s.user] || 0 });
    }

    return json({ error: "Nicht gefunden" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Serverfehler" }, 500);
  }
};

export const config = { path: "/api/*" };
