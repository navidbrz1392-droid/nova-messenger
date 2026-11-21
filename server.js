require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { Server } = require("socket.io");
const path = require("path");

const required = ["DATABASE_URL", "JWT_SECRET"];
for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
}
if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters.");
}

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: process.env.CLIENT_ORIGIN || "http://localhost:3000" }
});
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CLIENT_ORIGIN || "http://localhost:3000" }));
app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30 }));

const signToken = (user) => jwt.sign(
  { sub: String(user.id), username: user.username },
  process.env.JWT_SECRET,
  { expiresIn: "7d" }
);

async function authenticate(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (!token) return res.status(401).json({ error: "Authentication required." });
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session." });
  }
}

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body || {};
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username || "")) {
      return res.status(400).json({ error: "Username must be 3–32 letters, numbers or underscores." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || "")) {
      return res.status(400).json({ error: "A valid email is required." });
    }
    if (typeof password !== "string" || password.length < 12) {
      return res.status(400).json({ error: "Password must be at least 12 characters." });
    }
    const name = String(displayName || username).trim().slice(0, 80);
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users(username,email,password_hash,display_name)
       VALUES($1,$2,$3,$4)
       RETURNING id,username,email,display_name`,
      [username.toLowerCase(), email.toLowerCase(), hash, name]
    );
    const user = result.rows[0];
    res.status(201).json({ user, token: signToken(user) });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Username or email already exists." });
    console.error(err);
    res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const result = await pool.query(
      "SELECT id,username,email,display_name,password_hash FROM users WHERE email=$1",
      [String(email || "").toLowerCase()]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password || "", user.password_hash))) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }
    delete user.password_hash;
    res.json({ user, token: signToken(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not sign in." });
  }
});

app.get("/api/me", authenticate, async (req, res) => {
  const result = await pool.query(
    "SELECT id,username,email,display_name,created_at FROM users WHERE id=$1",
    [req.user.sub]
  );
  if (!result.rows[0]) return res.status(404).json({ error: "User not found." });
  res.json({ user: result.rows[0] });
});

app.get("/api/users", authenticate, async (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 40);
  if (q.length < 2) return res.json({ users: [] });
  const result = await pool.query(
    `SELECT id,username,display_name FROM users
     WHERE id <> $1 AND (username ILIKE $2 OR display_name ILIKE $2)
     ORDER BY username LIMIT 20`,
    [req.user.sub, `%${q}%`]
  );
  res.json({ users: result.rows });
});

app.post("/api/conversations/direct", authenticate, async (req, res) => {
  const otherId = Number(req.body && req.body.userId);
  if (!Number.isSafeInteger(otherId) || otherId === Number(req.user.sub)) {
    return res.status(400).json({ error: "A valid other user is required." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const found = await client.query(
      `SELECT c.id FROM conversations c
       JOIN conversation_members a ON a.conversation_id=c.id AND a.user_id=$1
       JOIN conversation_members b ON b.conversation_id=c.id AND b.user_id=$2
       WHERE c.kind='direct'
         AND (SELECT COUNT(*) FROM conversation_members m WHERE m.conversation_id=c.id)=2
       LIMIT 1`,
      [req.user.sub, otherId]
    );
    let conversationId;
    if (found.rows[0]) {
      conversationId = found.rows[0].id;
    } else {
      const exists = await client.query("SELECT id FROM users WHERE id=$1", [otherId]);
      if (!exists.rows[0]) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "User not found." });
      }
      const created = await client.query(
        "INSERT INTO conversations(kind) VALUES('direct') RETURNING id"
      );
      conversationId = created.rows[0].id;
      await client.query(
        "INSERT INTO conversation_members(conversation_id,user_id) VALUES($1,$2),($1,$3)",
        [conversationId, req.user.sub, otherId]
      );
    }
    await client.query("COMMIT");
    res.status(201).json({ conversationId });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Could not create conversation." });
  } finally {
    client.release();
  }
});

app.get("/api/conversations", authenticate, async (req, res) => {
  const result = await pool.query(
    `SELECT c.id,c.kind,c.title,
       (SELECT json_agg(json_build_object('id',u.id,'username',u.username,'displayName',u.display_name))
        FROM conversation_members cm JOIN users u ON u.id=cm.user_id
        WHERE cm.conversation_id=c.id AND u.id<>$1) AS participants,
       (SELECT json_build_object('body',m.body,'createdAt',m.created_at)
        FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message
     FROM conversations c
     JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=$1
     ORDER BY c.created_at DESC`,
    [req.user.sub]
  );
  res.json({ conversations: result.rows });
});

app.get("/api/conversations/:id/messages", authenticate, async (req, res) => {
  const id = Number(req.params.id);
  const member = await pool.query(
    "SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",
    [id, req.user.sub]
  );
  if (!member.rows.length) return res.status(403).json({ error: "Not a conversation member." });
  const result = await pool.query(
    `SELECT m.id,m.conversation_id,m.body,m.created_at,
       u.id AS sender_id,u.username,u.display_name
     FROM messages m JOIN users u ON u.id=m.sender_id
     WHERE m.conversation_id=$1 ORDER BY m.created_at DESC LIMIT 100`,
    [id]
  );
  res.json({ messages: result.rows.reverse() });
});

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  socket.on("conversation:join", async ({ conversationId } = {}) => {
    const id = Number(conversationId);
    if (!Number.isSafeInteger(id)) return;
    const member = await pool.query(
      "SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",
      [id, socket.user.sub]
    );
    if (member.rows.length) socket.join(`conversation:${id}`);
  });

  socket.on("message:send", async ({ conversationId, body } = {}, callback = () => {}) => {
    try {
      const id = Number(conversationId);
      const text = typeof body === "string" ? body.trim() : "";
      if (!Number.isSafeInteger(id) || !text || text.length > 5000) {
        return callback({ error: "Invalid message." });
      }
      const member = await pool.query(
        "SELECT 1 FROM conversation_members WHERE conversation_id=$1 AND user_id=$2",
        [id, socket.user.sub]
      );
      if (!member.rows.length) return callback({ error: "Not a conversation member." });

      const result = await pool.query(
        `INSERT INTO messages(conversation_id,sender_id,body)
         VALUES($1,$2,$3)
         RETURNING id,conversation_id,sender_id,body,created_at`,
        [id, socket.user.sub, text]
      );
      const message = result.rows[0];
      const sender = await pool.query(
        "SELECT username,display_name FROM users WHERE id=$1",
        [socket.user.sub]
      );
      const payload = { ...message, ...sender.rows[0] };
      io.to(`conversation:${id}`).emit("message:new", payload);
      callback({ ok: true, message: payload });
    } catch (err) {
      console.error(err);
      callback({ error: "Message could not be sent." });
    }
  });
});

app.get("/health", (_req, res) => res.json({ ok: true, service: "NOVA API" }));

const port = Number(process.env.PORT || 3000);
server.listen(port, () => console.log(`NOVA listening on http://localhost:${port}`));
