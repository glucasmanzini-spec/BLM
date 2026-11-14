const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
});
const uid = () => crypto.randomUUID();
const encoder = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = value => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4)), c => c.charCodeAt(0));

async function tokenFor(payload, secret) {
  const body = b64(encoder.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  return body + "." + b64(sig);
}
async function readToken(token, secret) {
  try {
    const [body, signature] = token.split(".");
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify("HMAC", key, unb64(signature), encoder.encode(body))) return null;
    const payload = JSON.parse(new TextDecoder().decode(unb64(body)));
    return payload.exp > Date.now() ? payload : null;
  } catch { return null; }
}
async function hashPassword(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/../g).map(x => parseInt(x, 16))) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, key, 256);
  return Array.from(salt, x => x.toString(16).padStart(2, "0")).join("") + ":" + b64(bits);
}
async function passwordMatches(password, stored) {
  const [salt, expected] = stored.split(":");
  return (await hashPassword(password, salt)).split(":")[1] === expected;
}
async function getUser(request, env) {
  const url = new URL(request.url);
  const bearer = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const token = bearer || (url.pathname.startsWith("/api/ws/") ? url.searchParams.get("token") : "");
  return token ? readToken(token, env.SESSION_SECRET) : null;
}
async function readBody(request) { try { return await request.json(); } catch { return {}; } }

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    try {
      if (url.pathname === "/api/register" && request.method === "POST") {
        const data = await readBody(request);
        const username = String(data.username || "").trim();
        const password = String(data.password || "");
        if (!/^[a-zA-Z0-9_]{3,24}$/.test(username) || password.length < 8 || password.length > 128)
          return json({ error: "Use um usuário de 3–24 caracteres e senha de pelo menos 8 caracteres." }, 400);
        const id = uid(), password_hash = await hashPassword(password);
        try {
          await env.DB.prepare("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)").bind(id, username, password_hash).run();
        } catch { return json({ error: "Esse nome de usuário já está em uso." }, 409); }
        const token = await tokenFor({ sub: id, username, exp: Date.now() + 7 * 86400000 }, env.SESSION_SECRET);
        return json({ token, user: { id, username } }, 201);
      }
      if (url.pathname === "/api/login" && request.method === "POST") {
        const data = await readBody(request), username = String(data.username || "").trim();
        const row = await env.DB.prepare("SELECT id, username, password_hash FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
        if (!row || !await passwordMatches(String(data.password || ""), row.password_hash)) return json({ error: "Usuário ou senha incorretos." }, 401);
        const token = await tokenFor({ sub: row.id, username: row.username, exp: Date.now() + 7 * 86400000 }, env.SESSION_SECRET);
        return json({ token, user: { id: row.id, username: row.username } });
      }

      const user = await getUser(request, env);
      if (!user) return json({ error: "Faça login para continuar." }, 401);
      if (url.pathname === "/api/me") return json({ user: { id: user.sub, username: user.username } });

      if (url.pathname === "/api/servers" && request.method === "GET") {
        const { results } = await env.DB.prepare("SELECT s.id, s.name FROM servers s JOIN memberships m ON m.server_id=s.id WHERE m.user_id=? ORDER BY s.created_at").bind(user.sub).all();
        return json({ servers: results });
      }
      if (url.pathname === "/api/servers" && request.method === "POST") {
        const name = String((await readBody(request)).name || "").trim().slice(0, 40);
        if (!name) return json({ error: "Digite um nome para o servidor." }, 400);
        const serverId = uid(), channelId = uid();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO servers (id,name,owner_id) VALUES (?,?,?)").bind(serverId, name, user.sub),
          env.DB.prepare("INSERT INTO memberships (server_id,user_id) VALUES (?,?)").bind(serverId, user.sub),
          env.DB.prepare("INSERT INTO channels (id,server_id,name) VALUES (?,?,?)").bind(channelId, serverId, "geral")
        ]);
        return json({ server: { id: serverId, name }, channel: { id: channelId, name: "geral" } }, 201);
      }

      const channelsRoute = url.pathname.match(/^\/api\/servers\/([^/]+)\/channels$/);
      if (channelsRoute) {
        const serverId = channelsRoute[1];
        const member = await env.DB.prepare("SELECT 1 FROM memberships WHERE server_id=? AND user_id=?").bind(serverId, user.sub).first();
        if (!member) return json({ error: "Servidor não encontrado." }, 404);
        if (request.method === "GET") {
          const { results } = await env.DB.prepare("SELECT id,name FROM channels WHERE server_id=? ORDER BY created_at").bind(serverId).all();
          return json({ channels: results });
        }
        if (request.method === "POST") {
          const name = String((await readBody(request)).name || "").trim().toLowerCase().replace(/[^a-z0-9-_]/g, "-").slice(0, 32);
          if (!name) return json({ error: "Nome de canal inválido." }, 400);
          const id = uid();
          await env.DB.prepare("INSERT INTO channels (id,server_id,name) VALUES (?,?,?)").bind(id, serverId, name).run();
          return json({ channel: { id, name } }, 201);
        }
      }

      const messagesRoute = url.pathname.match(/^\/api\/channels\/([^/]+)\/messages$/);
      if (messagesRoute && request.method === "GET") {
        const channelId = messagesRoute[1];
        const member = await env.DB.prepare("SELECT 1 FROM channels c JOIN memberships m ON m.server_id=c.server_id WHERE c.id=? AND m.user_id=?").bind(channelId, user.sub).first();
        if (!member) return json({ error: "Canal não encontrado." }, 404);
        const { results } = await env.DB.prepare("SELECT id,username,content,created_at FROM messages WHERE channel_id=? ORDER BY created_at DESC LIMIT 50").bind(channelId).all();
        return json({ messages: results.reverse() });
      }

      const wsRoute = url.pathname.match(/^\/api\/ws\/([^/]+)$/);
      if (wsRoute) {
        const channelId = wsRoute[1];
        const member = await env.DB.prepare("SELECT 1 FROM channels c JOIN memberships m ON m.server_id=c.server_id WHERE c.id=? AND m.user_id=?").bind(channelId, user.sub).first();
        if (!member) return json({ error: "Canal não encontrado." }, 404);
        const room = env.CHAT_ROOMS.get(env.CHAT_ROOMS.idFromName(channelId));
        const headers = new Headers(request.headers);
        headers.set("x-user-id", user.sub);
        headers.set("x-username", user.username);
        headers.set("x-channel-id", channelId);
        return room.fetch(new Request("https://room/ws", { headers }));
      }
      return json({ error: "Rota não encontrada." }, 404);
    } catch (error) {
      return json({ error: "Erro interno no Worker.", detail: String(error?.message || error) }, 500);
    }
  }
};

export class ChatRoom {
  constructor(state, env) { this.state = state; this.env = env; this.sessions = new Set(); }
  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("WebSocket required", { status: 426 });
    const userId = request.headers.get("x-user-id");
    const username = request.headers.get("x-username");
    const channelId = request.headers.get("x-channel-id");
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    this.sessions.add(server);
    server.addEventListener("message", async event => {
      try {
        const data = JSON.parse(event.data);
        if (data.type !== "message" || typeof data.content !== "string") return;
        const content = data.content.trim().slice(0, 2000);
        if (!content) return;
        const id = crypto.randomUUID();
        await this.env.DB.prepare("INSERT INTO messages (id,channel_id,user_id,username,content) VALUES (?,?,?,?,?)")
          .bind(id, channelId, userId, username, content).run();
        const message = JSON.stringify({ type: "message", message: { id, username, content, created_at: new Date().toISOString() } });
        for (const socket of this.sessions) {
          try { socket.send(message); } catch { this.sessions.delete(socket); }
        }
      } catch {}
    });
    const cleanup = () => this.sessions.delete(server);
    server.addEventListener("close", cleanup);
    server.addEventListener("error", cleanup);
    return new Response(null, { status: 101, webSocket: client });
  }
}
