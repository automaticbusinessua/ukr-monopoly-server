// ============================================================================
// ОНЛАЙН СЕРВЕР МУЛЬТИПЛЕЄРА ТА ЗАХИЩЕНА АДМІНКА
// Українська Монополія: Темки & Картелі (GTA Neon Edition)
// ============================================================================

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;

// Пароль адміністратора: підтримується як змінна ADMIN_PASSWORD в оточенні,
// так і зручні стандартні паролі (admin2026, Admin2026, admin).
const ADMIN_ALLOWED_PASSWORDS = process.env.ADMIN_PASSWORD
  ? [process.env.ADMIN_PASSWORD]
  : ["admin2026", "Admin2026", "admin"];

const ADMIN_SALT = crypto.randomBytes(16);
const ADMIN_SCRYPT_HASHES = ADMIN_ALLOWED_PASSWORDS.map(p => crypto.scryptSync(p, ADMIN_SALT, 64));

function verifyAdminPassword(pwd) {
  if (!pwd || typeof pwd !== "string") return false;
  try {
    const candidateHash = crypto.scryptSync(pwd.trim(), ADMIN_SALT, 64);
    for (const storedHash of ADMIN_SCRYPT_HASHES) {
      if (crypto.timingSafeEqual(storedHash, candidateHash)) return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

// Захищені сесії адміністратора з терміном дії (24 години)
const adminSessions = new Map(); // token -> { token, ip, userAgent, createdAt, expiresAt }
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function createAdminSession(ip, userAgent) {
  const token = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  adminSessions.set(token, {
    token,
    ip: ip || "unknown",
    userAgent: userAgent || "unknown",
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS
  });
  return token;
}

function isValidAdminToken(rawHeader) {
  if (!rawHeader || typeof rawHeader !== "string") return false;
  const token = rawHeader.startsWith("Bearer ") ? rawHeader.substring(7).trim() : rawHeader.trim();
  const session = adminSessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expiresAt) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

function destroyAdminSession(rawHeader) {
  if (!rawHeader) return;
  const token = rawHeader.startsWith("Bearer ") ? rawHeader.substring(7).trim() : rawHeader.trim();
  adminSessions.delete(token);
}

function destroyAllAdminSessions() {
  adminSessions.clear();
}

// Обмеження спроб входу за IP (Rate Limiter: макс 5 спроб за 10 хв)
const loginRateLimit = new Map(); // ip -> { count, firstTime, blockedUntil }
const failedLoginAuditLog = [];
const RATE_MAX_ATTEMPTS = 5;
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_BLOCK_MS = 10 * 60 * 1000;

function checkLoginRateLimit(ip) {
  const now = Date.now();
  const rec = loginRateLimit.get(ip);
  if (!rec) return { allowed: true };
  if (rec.blockedUntil && now < rec.blockedUntil) {
    return { allowed: false, remainingSec: Math.ceil((rec.blockedUntil - now) / 1000) };
  }
  if (now - rec.firstTime > RATE_WINDOW_MS) {
    loginRateLimit.delete(ip);
    return { allowed: true };
  }
  if (rec.count >= RATE_MAX_ATTEMPTS) {
    rec.blockedUntil = now + RATE_BLOCK_MS;
    return { allowed: false, remainingSec: Math.ceil(RATE_BLOCK_MS / 1000) };
  }
  return { allowed: true };
}

function recordFailedLoginAttempt(ip, userAgent) {
  const now = Date.now();
  let rec = loginRateLimit.get(ip);
  if (!rec || (now - rec.firstTime > RATE_WINDOW_MS && !rec.blockedUntil)) {
    rec = { count: 1, firstTime: now, blockedUntil: 0 };
    loginRateLimit.set(ip, rec);
  } else {
    rec.count += 1;
    if (rec.count >= RATE_MAX_ATTEMPTS) {
      rec.blockedUntil = now + RATE_BLOCK_MS;
    }
  }
  failedLoginAuditLog.unshift({
    ip,
    userAgent: userAgent || "unknown",
    timestamp: new Date().toISOString()
  });
  if (failedLoginAuditLog.length > 50) failedLoginAuditLog.pop();
}

function resetLoginRateLimit(ip) {
  loginRateLimit.delete(ip);
}

// Білий список роздачі статичних файлів
function isStaticPathAllowed(pathname) {
  const clean = path.posix.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
  const allowedExact = new Set([
    "/",
    "/index.html",
    "/shop",
    "/shop.html",
    "/print.html",
    "/robots.txt",
    "/sitemap.xml",
    "/admin",
    "/admin.html"
  ]);
  if (allowedExact.has(clean)) return true;

  if (clean.startsWith("/assets/") || clean.startsWith("/css/") || clean.startsWith("/js/")) {
    const ext = path.extname(clean).toLowerCase();
    const forbiddenExts = new Set([".json", ".env", ".md", ".sh", ".cmd", ".bat"]);
    if (clean.includes("..") || forbiddenExts.has(ext)) return false;
    return true;
  }
  return false;
}

// ----------------------------------------------------------------------------
// MIME ТИПИ ДЛЯ СТАТИЧНИХ ФАЙЛІВ
// ----------------------------------------------------------------------------
const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".pdf": "application/pdf",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".ttf": "font/ttf"
};

// ----------------------------------------------------------------------------
// КЕРУВАННЯ МУЛЬТИПЛЕЄРНИМИ КІМНАТАМИ ТА ЗАГАЛЬНИМ ОНЛАЙН-ЧАТОМ
// ----------------------------------------------------------------------------
const rooms = new Map();
const lobbySockets = new Set();

// Історія загального онлайн-чату сайту
const globalChatHistory = [];

function generateRoomId() {
  const prefix = ["KYIV", "PODIL", "PECHERSK", "ODESA", "LVIV", "DNIPRO", "TEMKA"][Math.floor(Math.random() * 7)];
  const num = Math.floor(10 + Math.random() * 90);
  return `${prefix}-${num}`;
}

function getLobbyRoomsList() {
  const list = [];
  rooms.forEach((r, id) => {
    list.push({
      id: r.id,
      name: r.name,
      hostId: r.hostId,
      hostName: r.hostName,
      playersCount: r.players.length,
      maxPlayers: r.settings.maxPlayers,
      botCount: r.settings.botCount,
      status: r.status, // "waiting" | "playing" | "finished"
      startingCash: r.settings.startingCash,
      mode: r.settings.mode || "classic",
      turnTimer: r.settings.turnTimer || 90,
      createdAt: r.createdAt,
      players: r.players.map(p => ({
        id: p.id,
        name: p.name,
        color: p.color,
        token: p.token,
        isHost: Boolean(p.isHost),
        ready: Boolean(p.ready)
      }))
    });
  });
  // Сортуємо: нові зверху, очікуючі перші
  list.sort((a, b) => (a.status === "waiting" ? -1 : 1) || b.createdAt - a.createdAt);
  return list;
}

function broadcastToLobby(msg) {
  const payload = JSON.stringify(msg);
  lobbySockets.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  });
}

function broadcastToRoom(roomId, msg, excludeWs = null) {
  const r = rooms.get(roomId);
  if (!r) return;
  const payload = JSON.stringify(msg);
  r.players.forEach(p => {
    if (p.ws && p.ws !== excludeWs && p.ws.readyState === WebSocket.OPEN) {
      p.ws.send(payload);
    }
  });
}

// ----------------------------------------------------------------------------
// HTTP СЕРВЕР
// ----------------------------------------------------------------------------
const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  let pathname = decodeURIComponent(parsedUrl.pathname);
  const clientIp = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
  const userAgent = req.headers["user-agent"] || "";

  // Базові заголовки кібербезпеки та CORS для підключення з Cloudflare Pages
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' http: https: ws: wss:; font-src 'self' https://fonts.gstatic.com;");

  // Healthcheck для хмарних платформ (Render, Railway тощо)
  if (pathname === "/health" || (pathname === "/" && !fs.existsSync(path.join(ROOT_DIR, "index.html")))) {
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ status: "ok", service: "ukr-monopoly-ws", rooms: rooms.size }));
    return;
  }

  // Заборона індексації адмін-панелі пошуковими системами
  if (pathname === "/admin" || pathname === "/admin.html") {
    res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  }

  // API для адмінки: Авторизація із захистом від брутфорсу (5 спроб / 10 хв)
  if (pathname === "/api/admin/login" && req.method === "POST") {
    const rateCheck = checkLoginRateLimit(clientIp);
    if (!rateCheck.allowed) {
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        success: false,
        error: `Забагато невдалих спроб входу з вашої IP-адреси. Спробуйте через ${rateCheck.remainingSec} сек.`
      }));
      return;
    }

    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", () => {
      try {
        const { password } = JSON.parse(body);
        if (verifyAdminPassword(password)) {
          resetLoginRateLimit(clientIp);
          const token = createAdminSession(clientIp, userAgent);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, token }));
        } else {
          recordFailedLoginAttempt(clientIp, userAgent);
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: false, error: "Невірний пароль адміністратора" }));
        }
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, error: "Помилка формату даних" }));
      }
    });
    return;
  }

  // API для адмінки: Вихід з поточної сесії
  if (pathname === "/api/admin/logout" && req.method === "POST") {
    const authHeader = req.headers["authorization"];
    destroyAdminSession(authHeader);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // API для адмінки: «Вийти скрізь» (інвалідація всіх активних сесій)
  if (pathname === "/api/admin/logout-all" && req.method === "POST") {
    const authHeader = req.headers["authorization"];
    if (!isValidAdminToken(authHeader)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }
    destroyAllAdminSessions();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // API для адмінки: Список невдалих спроб входу (Журнал безпеки)
  if (pathname === "/api/admin/failed-logins" && req.method === "GET") {
    const authHeader = req.headers["authorization"];
    if (!isValidAdminToken(authHeader)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ attempts: failedLoginAuditLog }));
    return;
  }

  // API для адмінки: Список активних кімнат
  if (pathname === "/api/admin/rooms" && req.method === "GET") {
    const authHeader = req.headers["authorization"];
    if (!isValidAdminToken(authHeader)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }
    const fullRooms = [];
    rooms.forEach(r => {
      fullRooms.push({
        id: r.id,
        name: r.name,
        hostName: r.hostName,
        status: r.status,
        players: r.players.map(p => ({
          id: p.id,
          name: p.name,
          color: p.color,
          token: p.token,
          isBot: p.isBot,
          cash: p.cash,
          ready: p.ready
        })),
        createdAt: r.createdAt
      });
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ rooms: fullRooms, total: fullRooms.length, uptime: process.uptime() }));
    return;
  }

  // API для адмінки: Закрити кімнату
  if (pathname === "/api/admin/rooms/close" && req.method === "POST") {
    const authHeader = req.headers["authorization"];
    if (!isValidAdminToken(authHeader)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", () => {
      try {
        const { roomId, reason } = JSON.parse(body);
        if (rooms.has(roomId)) {
          broadcastToRoom(roomId, {
            type: "ROOM_CLOSED",
            reason: reason || "Кімнату закрито адміністратором"
          });
          rooms.delete(roomId);
          broadcastToLobby({ type: "ROOMS_UPDATED", rooms: getLobbyRoomsList() });
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // API для клієнта: Отримати відкриті кімнати (HTTP fallback)
  if (pathname === "/api/rooms" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ rooms: getLobbyRoomsList() }));
    return;
  }

  // Захищений маршрут до адмінки: /admin або /admin.html
  if (pathname === "/admin" || pathname === "/admin.html") {
    pathname = "/admin.html";
  }

  // Магазин фізичної гри: /shop → /shop.html
  if (pathname === "/shop") {
    pathname = "/shop.html";
  }

  // Маршрутизація головної сторінки
  if (pathname === "/") {
    pathname = "/index.html";
  }

  // БІЛИЙ СПИСОК РОЗДАЧІ СТАТИЧНИХ ФАЙЛІВ
  if (!isStaticPathAllowed(pathname)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("403 Доступ заборонено (White-list policy)");
    return;
  }

  // Віддача дозволеного статичного файлу
  const safePath = path.normalize(path.join(ROOT_DIR, pathname));
  if (!safePath.startsWith(ROOT_DIR)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("403 Доступ заборонено");
    return;
  }

  fs.stat(safePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("404 Не знайдено");
      return;
    }

    const ext = path.extname(safePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": contentType,
      "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=3600"
    });
    fs.createReadStream(safePath).pipe(res);
  });
});

// ----------------------------------------------------------------------------
// WEBSOCKET СЕРВЕР (РЕАЛЬНИЙ ЧАС ДЛЯ КІМНАТ ТА ГРИ)
// ----------------------------------------------------------------------------
const wss = new WebSocketServer({ server });

wss.on("connection", (ws, req) => {
  let clientRoomId = null;
  let clientPlayerId = null;
  let isLobbySubscriber = false;

  ws.on("message", raw => {
    try {
      const data = JSON.parse(raw.toString());

      switch (data.type) {
        // Підписка на оновлення списку кімнат у лобі та чат сайту
        case "LOBBY_SUBSCRIBE": {
          isLobbySubscriber = true;
          lobbySockets.add(ws);
          ws.send(JSON.stringify({
            type: "ROOMS_UPDATED",
            rooms: getLobbyRoomsList()
          }));
          ws.send(JSON.stringify({
            type: "GLOBAL_CHAT_HISTORY",
            messages: globalChatHistory
          }));
          break;
        }

        // Запит історії загального чату сайту
        case "GET_GLOBAL_CHAT": {
          ws.send(JSON.stringify({
            type: "GLOBAL_CHAT_HISTORY",
            messages: globalChatHistory
          }));
          break;
        }

        // Відправка повідомлення в загальний чат сайту
        case "GLOBAL_CHAT_SEND": {
          const text = String(data.text || "").trim().substring(0, 200);
          if (!text) break;
          const chatMsg = {
            id: "gc_" + Date.now() + "_" + Math.random().toString(36).substring(2, 6),
            senderName: String(data.senderName || "Темщик").trim().substring(0, 25),
            senderToken: String(data.senderToken || "🏎️").substring(0, 4),
            senderColor: String(data.senderColor || "#3B82F6"),
            text: text,
            time: new Date().toLocaleTimeString("uk-UA", { hour: "2-digit", minute: "2-digit" })
          };
          globalChatHistory.push(chatMsg);
          if (globalChatHistory.length > 100) globalChatHistory.shift();

          const payload = JSON.stringify({
            type: "GLOBAL_CHAT_MESSAGE",
            message: chatMsg
          });
          wss.clients.forEach(c => {
            if (c.readyState === WebSocket.OPEN) {
              c.send(payload);
            }
          });
          break;
        }

        // Створення нової онлайн-кімнати
        case "CREATE_ROOM": {
          const roomId = generateRoomId();
          const hostId = "p_" + Math.random().toString(36).substring(2, 9);
          const roomName = (data.roomName || "Темка на районі").trim().substring(0, 40);
          const hostName = (data.playerName || "Головний Темщик").trim().substring(0, 25);
          const startingCash = Number(data.startingCash) || 15000;
          const maxPlayers = Math.min(4, Math.max(2, Number(data.maxPlayers) || 4));
          const botCount = Math.min(maxPlayers - 1, Math.max(0, Number(data.botCount) || 0));
          const mode = data.mode === "turbo" ? "turbo" : "classic";
          const turnTimer = [60, 90, 120].includes(Number(data.turnTimer)) ? Number(data.turnTimer) : 90;

          const hostPlayer = {
            id: hostId,
            name: hostName,
            color: data.color || "#2ED573",
            token: data.token || "🏎️",
            isBot: false,
            isHost: true,
            ready: true,
            cash: startingCash,
            position: 0,
            inJail: false,
            jailTurns: 0,
            connection: null,
            bankrupt: false,
            ws: ws
          };

          const roomPlayers = [hostPlayer];

          // Ініціалізація стану клітинок (всі 28 клітинок)
          const initTileState = {};
          for (let i = 0; i < 28; i++) {
            initTileState[i] = { ownerId: null, stars: 0, mortgaged: false };
          }

          // Створюємо кімнату
          const newRoom = {
            id: roomId,
            name: roomName,
            hostId: hostId,
            hostName: hostName,
            status: "waiting", // "waiting" | "playing" | "finished"
            createdAt: Date.now(),
            settings: {
              startingCash: startingCash,
              maxPlayers: maxPlayers,
              botCount: botCount,
              mode: mode,
              turnTimer: turnTimer
            },
            players: roomPlayers,
            currentTurnIndex: 0,
            offshorePot: 500,
            tileState: initTileState,
            chat: []
          };

          rooms.set(roomId, newRoom);
          clientRoomId = roomId;
          clientPlayerId = hostId;

          // Відповідаємо хосту
          ws.send(JSON.stringify({
            type: "ROOM_CREATED",
            room: serializeRoom(newRoom),
            myPlayerId: hostId
          }));

          // Сповіщаємо лобі про нову кімнату
          broadcastToLobby({
            type: "ROOMS_UPDATED",
            rooms: getLobbyRoomsList()
          });
          break;
        }

        // Приєднання до існуючої онлайн-кімнати
        case "JOIN_ROOM": {
          const r = rooms.get(data.roomId);
          if (!r) {
            ws.send(JSON.stringify({ type: "ERROR", message: "Кімнату не знайдено!" }));
            return;
          }
          if (r.status !== "waiting" && !r.players.some(p => p.id === data.reconnectPlayerId)) {
            ws.send(JSON.stringify({ type: "ERROR", message: "Партія в цій кімнаті вже розпочалася!" }));
            return;
          }
          if (r.players.length >= r.settings.maxPlayers && !r.players.some(p => p.id === data.reconnectPlayerId)) {
            ws.send(JSON.stringify({ type: "ERROR", message: "У кімнаті вже максимальна кількість гравців!" }));
            return;
          }

          // Перевірка реконекту
          let player = r.players.find(p => p.id === data.reconnectPlayerId);
          if (player) {
            player.ws = ws;
          } else {
            const playerId = "p_" + Math.random().toString(36).substring(2, 9);
            const pName = (data.playerName || `Гравець #${r.players.length + 1}`).trim().substring(0, 25);
            player = {
              id: playerId,
              name: pName,
              color: data.color || getRandomColor(r.players),
              token: data.token || getRandomToken(r.players),
              isBot: false,
              isHost: false,
              ready: false,
              cash: r.settings.startingCash,
              position: 0,
              inJail: false,
              jailTurns: 0,
              connection: null,
              bankrupt: false,
              ws: ws
            };
            r.players.push(player);
          }

          clientRoomId = r.id;
          clientPlayerId = player.id;

          // Відповідаємо гравцю
          ws.send(JSON.stringify({
            type: "ROOM_JOINED",
            room: serializeRoom(r),
            myPlayerId: player.id
          }));

          // Сповіщаємо решту учасників кімнати
          broadcastToRoom(r.id, {
            type: "ROOM_UPDATED",
            room: serializeRoom(r)
          });

          // Оновлюємо лобі
          broadcastToLobby({
            type: "ROOMS_UPDATED",
            rooms: getLobbyRoomsList()
          });
          break;
        }

        // Зміна статусу готовності
        case "SET_READY": {
          const r = rooms.get(clientRoomId);
          if (!r) return;
          const p = r.players.find(x => x.id === clientPlayerId);
          if (p) {
            p.ready = Boolean(data.ready);
            broadcastToRoom(r.id, {
              type: "ROOM_UPDATED",
              room: serializeRoom(r)
            });
          }
          break;
        }

        // Вигнання гравця хостом (Capitalisto Host Control)
        case "KICK_PLAYER": {
          const r = rooms.get(clientRoomId);
          if (!r || r.hostId !== clientPlayerId) return;
          const targetIndex = r.players.findIndex(p => p.id === data.targetPlayerId && !p.isHost);
          if (targetIndex !== -1) {
            const kicked = r.players[targetIndex];
            r.players.splice(targetIndex, 1);
            if (kicked.ws && kicked.ws.readyState === WebSocket.OPEN) {
              kicked.ws.send(JSON.stringify({ type: "KICKED_FROM_ROOM", message: "Хост вилучив вас із кімнати." }));
            }
            broadcastToRoom(r.id, { type: "ROOM_UPDATED", room: serializeRoom(r) });
            broadcastToLobby({ type: "ROOMS_UPDATED", rooms: getLobbyRoomsList() });
          }
          break;
        }

        // Початок гри (тільки хост)
        case "START_GAME": {
          const r = rooms.get(clientRoomId);
          if (!r || r.hostId !== clientPlayerId) return;

          // Додаємо ШІ-ботів, якщо налаштовано
          if (r.settings.botCount > 0 && r.players.length < r.settings.maxPlayers) {
            const botsNeeded = Math.min(r.settings.botCount, r.settings.maxPlayers - r.players.length);
            const botNames = [
              { name: "Богдан «Темщик»", color: "#F27D21", token: "💼" },
              { name: "Микола «Депутат»", color: "#4AA8EE", token: "🏛️" },
              { name: "Артем «Криптовик»", color: "#A55EEA", token: "🪙" }
            ];
            for (let i = 0; i < botsNeeded; i++) {
              const b = botNames[i % botNames.length];
              r.players.push({
                id: `bot_${i + 1}_${Date.now()}`,
                name: b.name,
                color: b.color,
                token: b.token,
                isBot: true,
                isHost: false,
                ready: true,
                cash: r.settings.startingCash,
                position: 0,
                inJail: false,
                jailTurns: 0,
                connection: null,
                bankrupt: false,
                ws: null
              });
            }
          }

          r.status = "playing";
          r.currentTurnIndex = 0;

          broadcastToRoom(r.id, {
            type: "GAME_STARTED",
            room: serializeRoom(r)
          });

          broadcastToLobby({
            type: "ROOMS_UPDATED",
            rooms: getLobbyRoomsList()
          });

          // Якщо перший хід у бота — запускаємо хід бота
          checkAndRunBotTurn(r);
          break;
        }

        // Ігрові дії (Кидок кубиків, покупка, апгрейд, зв'язок, завершення ходу)
        case "GAME_ACTION": {
          const r = rooms.get(clientRoomId);
          if (!r || r.status !== "playing") return;

          handleGameAction(r, clientPlayerId, data.action, data.payload, ws);
          break;
        }

        // Повідомлення чату кімнати
        case "CHAT_MESSAGE": {
          const r = rooms.get(clientRoomId);
          if (!r) return;
          const p = r.players.find(x => x.id === clientPlayerId);
          const text = String(data.text || "").trim().substring(0, 150);
          if (!text || !p) return;

          const chatItem = {
            id: Date.now() + "_" + Math.random().toString(36).substring(2, 6),
            senderId: p.id,
            senderName: p.name,
            senderColor: p.color,
            text: text,
            time: new Date().toLocaleTimeString("uk-UA", { hour: "2-digit", minute: "2-digit" })
          };

          r.chat.push(chatItem);
          if (r.chat.length > 50) r.chat.shift();

          broadcastToRoom(r.id, {
            type: "CHAT_MESSAGE",
            message: chatItem
          });
          break;
        }

        // Вихід з кімнати
        case "LEAVE_ROOM": {
          handlePlayerLeave(clientRoomId, clientPlayerId);
          clientRoomId = null;
          clientPlayerId = null;
          break;
        }
      }
    } catch (err) {
      console.error("WS error:", err.message);
    }
  });

  ws.on("close", () => {
    if (isLobbySubscriber) {
      lobbySockets.delete(ws);
    }
    if (clientRoomId && clientPlayerId) {
      handlePlayerDisconnect(clientRoomId, clientPlayerId);
    }
  });
});

function handlePlayerDisconnect(roomId, playerId) {
  const r = rooms.get(roomId);
  if (!r) return;
  const p = r.players.find(x => x.id === playerId);
  if (p) p.ws = null;

  // Рахуємо підключених живих людей
  const connectedHumans = r.players.filter(pl => !pl.isBot && pl.ws && pl.ws.readyState === WebSocket.OPEN);

  if (r.status === "waiting") {
    handlePlayerLeave(roomId, playerId);
  } else {
    // Якщо під час партії всі люди відключилися — кімната негайно закривається і не зависає
    if (connectedHumans.length === 0) {
      rooms.delete(roomId);
      broadcastToLobby({
        type: "ROOMS_UPDATED",
        rooms: getLobbyRoomsList()
      });
    } else {
      if (r.hostId === playerId && connectedHumans.length > 0) {
        r.hostId = connectedHumans[0].id;
        r.hostName = connectedHumans[0].name;
        connectedHumans[0].isHost = true;
      }
      broadcastToRoom(r.id, {
        type: "PLAYER_DISCONNECTED",
        playerId: playerId
      });
      broadcastToLobby({
        type: "ROOMS_UPDATED",
        rooms: getLobbyRoomsList()
      });
    }
  }
}

function handlePlayerLeave(roomId, playerId) {
  const r = rooms.get(roomId);
  if (!r) return;

  r.players = r.players.filter(p => p.id !== playerId);
  const remainingHumans = r.players.filter(p => !p.isBot);

  if (remainingHumans.length === 0) {
    rooms.delete(roomId);
  } else {
    if (r.hostId === playerId) {
      const nextHuman = remainingHumans[0];
      r.hostId = nextHuman.id;
      r.hostName = nextHuman.name;
      nextHuman.isHost = true;
    }
    broadcastToRoom(r.id, {
      type: "ROOM_UPDATED",
      room: serializeRoom(r)
    });
  }

  broadcastToLobby({
    type: "ROOMS_UPDATED",
    rooms: getLobbyRoomsList()
  });
}

// Автоматичне очищення старих та завислих кімнат (кожні 10 секунд)
setInterval(() => {
  const now = Date.now();
  let changed = false;

  rooms.forEach((r, roomId) => {
    const connectedHumans = r.players.filter(p => !p.isBot && p.ws && p.ws.readyState === WebSocket.OPEN);

    // 1. Жодного підключеного гравця-людини
    if (connectedHumans.length === 0) {
      rooms.delete(roomId);
      changed = true;
      return;
    }

    // 2. Кімната в очікуванні (waiting) створена понад 15 хвилин тому
    if (r.status === "waiting" && now - r.createdAt > 15 * 60 * 1000) {
      broadcastToRoom(roomId, { type: "ROOM_CLOSED", reason: "Кімнату закрито через неактивність (таймаут)" });
      rooms.delete(roomId);
      changed = true;
      return;
    }

    // 3. Зависла партія без дій понад 30 хвилин
    const lastActive = r.lastActivityAt || r.createdAt;
    if (now - lastActive > 30 * 60 * 1000) {
      broadcastToRoom(roomId, { type: "ROOM_CLOSED", reason: "Партію закрито через тривалий простій" });
      rooms.delete(roomId);
      changed = true;
      return;
    }
  });

  if (changed) {
    broadcastToLobby({
      type: "ROOMS_UPDATED",
      rooms: getLobbyRoomsList()
    });
  }
}, 10000);

// ----------------------------------------------------------------------------
// СИНХРОНІЗАЦІЯ ІГРОВИХ ДІЙ
// ----------------------------------------------------------------------------
function handleGameAction(room, playerId, action, payload, senderWs) {
  const curPlayer = room.players[room.currentTurnIndex];
  if (!curPlayer) return;

  // Дії ходу дозволені поточному гравцю (або хосту для загальних синхронізацій)
  switch (action) {
    case "ROLL_DICE": {
      if (curPlayer.id !== playerId && !curPlayer.isBot) return;

      const d1 = payload?.dice ? payload.dice[0] : Math.floor(1 + Math.random() * 6);
      const d2 = payload?.dice ? payload.dice[1] : Math.floor(1 + Math.random() * 6);
      const steps = payload?.steps || (d1 + d2);
      const isDouble = d1 === d2;

      const oldPos = typeof payload?.fromPos === "number" ? payload.fromPos : curPlayer.position;
      const newPos = (oldPos + steps) % 28;
      const passedGo = newPos < oldPos;

      curPlayer.position = newPos;

      broadcastToRoom(room.id, {
        type: "ACTION_BROADCAST",
        action: "DICE_ROLLED",
        playerId: payload?.playerId || curPlayer.id,
        dice: [d1, d2],
        isDouble: isDouble,
        steps: steps,
        fromPos: oldPos,
        oldPosition: oldPos,
        newPosition: newPos,
        passedGo: passedGo
      }, senderWs);
      break;
    }

    case "BUY_PROPERTY": {
      const tileIndex = Number(payload.tileIndex);
      const price = Number(payload.price);
      if (curPlayer.id === playerId && curPlayer.cash >= price) {
        curPlayer.cash -= price;
        room.tileState[tileIndex] = {
          ownerId: curPlayer.id,
          stars: 0,
          mortgaged: false
        };
        broadcastToRoom(room.id, {
          type: "ACTION_BROADCAST",
          action: "PROPERTY_BOUGHT",
          playerId: curPlayer.id,
          tileIndex: tileIndex,
          price: price,
          newCash: curPlayer.cash
        });
      }
      break;
    }

    case "UPGRADE_PROPERTY": {
      const tileIndex = Number(payload.tileIndex);
      const cost = Number(payload.cost);
      const st = room.tileState[tileIndex];
      if (st && st.ownerId === curPlayer.id && curPlayer.cash >= cost && st.stars < 3) {
        curPlayer.cash -= cost;
        st.stars += 1;
        broadcastToRoom(room.id, {
          type: "ACTION_BROADCAST",
          action: "PROPERTY_UPGRADED",
          playerId: curPlayer.id,
          tileIndex: tileIndex,
          stars: st.stars,
          cost: cost,
          newCash: curPlayer.cash
        });
      }
      break;
    }

    case "MORTGAGE_TOGGLE": {
      const tileIndex = Number(payload.tileIndex);
      const st = room.tileState[tileIndex];
      if (st && st.ownerId === playerId) {
        st.mortgaged = !st.mortgaged;
        const delta = payload.cashDelta || 0;
        const p = room.players.find(x => x.id === playerId);
        if (p) p.cash += delta;

        broadcastToRoom(room.id, {
          type: "ACTION_BROADCAST",
          action: "MORTGAGE_TOGGLED",
          playerId: playerId,
          tileIndex: tileIndex,
          mortgaged: st.mortgaged,
          newCash: p ? p.cash : 0
        });
      }
      break;
    }

    case "BUY_CONNECTION": {
      const connId = payload.connectionId;
      const price = Number(payload.price);
      if (curPlayer.id === playerId && curPlayer.cash >= price) {
        curPlayer.cash -= price;
        curPlayer.connection = connId;
        broadcastToRoom(room.id, {
          type: "ACTION_BROADCAST",
          action: "CONNECTION_BOUGHT",
          playerId: curPlayer.id,
          connectionId: connId,
          price: price,
          newCash: curPlayer.cash
        });
      }
      break;
    }

    case "PAY_RENT": {
      const owner = room.players.find(x => x.id === payload.ownerId);
      const amount = Number(payload.amount);
      if (curPlayer.id === playerId && owner) {
        curPlayer.cash -= amount;
        owner.cash += amount;
        broadcastToRoom(room.id, {
          type: "ACTION_BROADCAST",
          action: "RENT_PAID",
          fromPlayerId: curPlayer.id,
          toPlayerId: owner.id,
          amount: amount,
          fromCash: curPlayer.cash,
          toCash: owner.cash
        });
      }
      break;
    }

    case "CASINO_RESULT": {
      const netWin = Number(payload.netWin);
      curPlayer.cash += netWin;
      broadcastToRoom(room.id, {
        type: "ACTION_BROADCAST",
        action: "CASINO_RESOLVED",
        playerId: curPlayer.id,
        netWin: netWin,
        diceSequence: payload.diceSequence,
        multiplier: payload.multiplier,
        newCash: curPlayer.cash
      });
      break;
    }

    case "END_TURN": {
      // Перехід до наступного незабанкрутілого гравця
      let nextIdx = (room.currentTurnIndex + 1) % room.players.length;
      let count = 0;
      while (room.players[nextIdx].bankrupt && count < room.players.length) {
        nextIdx = (nextIdx + 1) % room.players.length;
        count++;
      }

      room.currentTurnIndex = nextIdx;
      const nextPlayer = room.players[nextIdx];

      broadcastToRoom(room.id, {
        type: "ACTION_BROADCAST",
        action: "TURN_ENDED",
        nextTurnIndex: nextIdx,
        nextPlayerId: nextPlayer.id,
        nextPlayerName: nextPlayer.name
      });

      // Перевіряємо, чи наступний хід у бота
      checkAndRunBotTurn(room);
      break;
    }

    case "SYNC_FULL_STATE": {
      if (!payload) break;
      if (Array.isArray(payload.players)) {
        payload.players.forEach(sp => {
          const target = room.players.find(p => p.id === sp.id);
          if (target) {
            target.cash = typeof sp.cash === "number" ? sp.cash : target.cash;
            target.position = typeof sp.position === "number" ? sp.position : target.position;
            target.inJail = Boolean(sp.inJail);
            target.jailTurns = sp.jailTurns || 0;
            target.connection = sp.connection || null;
            target.bankrupt = Boolean(sp.bankrupt);
            target.immunityTurns = sp.immunityTurns || 0;
          }
        });
      }
      if (payload.tileState) {
        room.tileState = payload.tileState;
      }
      if (payload.offshorePot !== undefined) {
        room.offshorePot = payload.offshorePot;
      }
      if (typeof payload.currentTurnIndex === "number") {
        room.currentTurnIndex = payload.currentTurnIndex;
      }
      if (payload.turnPhase) {
        room.turnPhase = payload.turnPhase;
      }
      if (Array.isArray(payload.lastDice)) {
        room.lastDice = payload.lastDice;
      }
      if (typeof payload.selectedTileIndex === "number") {
        room.selectedTileIndex = payload.selectedTileIndex;
      }
      if (typeof payload.doublesCount === "number") {
        room.doublesCount = payload.doublesCount;
      }
      if (Array.isArray(payload.recentLogs)) {
        room.recentLogs = payload.recentLogs;
      }

      const serialized = serializeRoom(room);
      serialized.turnPhase = room.turnPhase;
      serialized.lastDice = room.lastDice;
      serialized.selectedTileIndex = room.selectedTileIndex;
      serialized.doublesCount = room.doublesCount;
      serialized.recentLogs = room.recentLogs;

      broadcastToRoom(room.id, {
        type: "ACTION_BROADCAST",
        action: "STATE_SYNCED",
        room: serialized
      }, senderWs);
      break;
    }
  }
}

// Автоматичний хід бота в кімнаті з таймером
function checkAndRunBotTurn(room) {
  const curPlayer = room.players[room.currentTurnIndex];
  if (!curPlayer || !curPlayer.isBot || curPlayer.bankrupt) return;

  setTimeout(() => {
    // Переконуємось, що це досі хід цього бота
    if (room.players[room.currentTurnIndex]?.id !== curPlayer.id) return;

    // Кидок кубика
    const d1 = Math.floor(1 + Math.random() * 6);
    const d2 = Math.floor(1 + Math.random() * 6);
    const steps = d1 + d2;
    const oldPos = curPlayer.position;
    const newPos = (oldPos + steps) % 28;
    const passedGo = newPos < oldPos;

    curPlayer.position = newPos;
    if (passedGo) curPlayer.cash += 2000;

    broadcastToRoom(room.id, {
      type: "ACTION_BROADCAST",
      action: "DICE_ROLLED",
      playerId: curPlayer.id,
      dice: [d1, d2],
      isDouble: d1 === d2,
      steps: steps,
      oldPosition: oldPos,
      newPosition: newPos,
      passedGo: passedGo,
      playerCash: curPlayer.cash
    });

    // Завершуємо хід бота через 1.8 секунди для реалістичного сприйняття
    setTimeout(() => {
      let nextIdx = (room.currentTurnIndex + 1) % room.players.length;
      let count = 0;
      while (room.players[nextIdx].bankrupt && count < room.players.length) {
        nextIdx = (nextIdx + 1) % room.players.length;
        count++;
      }
      room.currentTurnIndex = nextIdx;
      const nextPlayer = room.players[nextIdx];

      broadcastToRoom(room.id, {
        type: "ACTION_BROADCAST",
        action: "TURN_ENDED",
        nextTurnIndex: nextIdx,
        nextPlayerId: nextPlayer.id,
        nextPlayerName: nextPlayer.name
      });

      checkAndRunBotTurn(room);
    }, 1800);
  }, 1200);
}

// Серіалізація кімнати для клієнтів (без об'єктів сокетів)
function serializeRoom(r) {
  return {
    id: r.id,
    name: r.name,
    hostId: r.hostId,
    hostName: r.hostName,
    status: r.status,
    createdAt: r.createdAt,
    settings: r.settings,
    currentTurnIndex: r.currentTurnIndex,
    offshorePot: r.offshorePot,
    tileState: r.tileState,
    players: r.players.map(p => ({
      id: p.id,
      name: p.name,
      color: p.color,
      token: p.token,
      isBot: p.isBot,
      isHost: p.isHost,
      ready: p.ready,
      cash: p.cash,
      position: p.position,
      inJail: p.inJail,
      jailTurns: p.jailTurns,
      connection: p.connection,
      bankrupt: p.bankrupt
    })),
    chat: r.chat
  };
}

const PALETTE = ["#2ED573", "#F0B929", "#FF4757", "#4AA8EE", "#A55EEA", "#FFA502", "#1E90FF"];
const TOKENS = ["🏎️", "🚁", "🛥️", "💼", "🕶️", "🪙", "🐯", "👑", "⚡", "🎲"];

function getRandomColor(existingPlayers) {
  const used = new Set(existingPlayers.map(p => p.color));
  const available = PALETTE.filter(c => !used.has(c));
  return available.length ? available[0] : PALETTE[Math.floor(Math.random() * PALETTE.length)];
}

function getRandomToken(existingPlayers) {
  const used = new Set(existingPlayers.map(p => p.token));
  const available = TOKENS.filter(t => !used.has(t));
  return available.length ? available[0] : TOKENS[Math.floor(Math.random() * TOKENS.length)];
}

// ----------------------------------------------------------------------------
// СТАРТ СЕРВЕРА
// ----------------------------------------------------------------------------
server.listen(PORT, () => {
  console.log(`================================================================`);
  console.log(`🚀 Сервер Української Монополії успішно запущено на порту ${PORT}!`);
  console.log(`🎮 Клієнтська гра:       http://localhost:${PORT}/`);
  console.log(`📊 Панель керування:    http://localhost:${PORT}/admin.html`);
  console.log(`================================================================`);
});
