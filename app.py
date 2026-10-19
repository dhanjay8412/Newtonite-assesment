"""Operations Under Pressure - Production Grade Mission-Critical Work-Item Dispatcher.
Stdlib only (Python 3.9+), SQLite WAL mode, Optimistic Concurrency, RBAC, Async Outbox."""
import sqlite3, json, hashlib, secrets, time, re, os, sys, random, csv, io
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DB = os.environ.get("DB", "ops.db")
SERVER_START_TIME = time.time()
TOKEN_TTL = int(os.environ.get("TOKEN_TTL_SECONDS", 86400))  # 24 hours
RANK = {"viewer": 1, "member": 2, "lead": 3, "admin": 4}
PRI = ["low", "normal", "high", "urgent"]
TYPES = ["incident", "customer_issue", "payment", "compliance", "task"]
FLOW = {
    "open": ["in_progress"],
    "in_progress": ["awaiting_approval", "open"],
    "awaiting_approval": ["resolved", "in_progress"],
    "resolved": ["closed", "open"],
    "closed": []
}
LEAD_ONLY = {("awaiting_approval", "resolved"), ("awaiting_approval", "in_progress")}

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 10000;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE, salt TEXT, pw TEXT, created_at REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY, name TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS memberships(user_id INT, team_id INT, role TEXT, PRIMARY KEY(user_id,team_id));
CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, user_id INT, expires_at REAL);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, title TEXT, description TEXT DEFAULT '', type TEXT,
  priority TEXT, status TEXT DEFAULT 'open', team_id INT, assignee_id INT, created_by INT, due_date TEXT,
  tags TEXT DEFAULT '', version INT DEFAULT 1, created_at REAL, updated_at REAL);
CREATE INDEX IF NOT EXISTS ix_team_status ON items(team_id,status,id);
CREATE INDEX IF NOT EXISTS ix_assignee ON items(assignee_id,status);
CREATE INDEX IF NOT EXISTS ix_unassigned ON items(priority,status) WHERE assignee_id IS NULL;
CREATE INDEX IF NOT EXISTS ix_due_date ON items(due_date);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, item_id INT, actor_id INT, type TEXT, data TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS ix_events_item ON events(item_id,id);
CREATE TABLE IF NOT EXISTS idem(user_id INT, key TEXT, code INT, response TEXT, PRIMARY KEY(user_id,key));
CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, kind TEXT, payload TEXT, status TEXT DEFAULT 'pending',
  attempts INT DEFAULT 0, next_run REAL DEFAULT 0, created_at REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS notifications(job_id INTEGER PRIMARY KEY, user_id INT, message TEXT, created_at REAL DEFAULT 0);
"""

class E(Exception):
    def __init__(s, code, msg, extra=None): s.code, s.msg, s.extra = code, msg, extra or {}

def db():
    c = sqlite3.connect(DB, timeout=15, isolation_level=None)
    c.execute("PRAGMA journal_mode = WAL;")
    c.execute("PRAGMA synchronous = NORMAL;")
    c.execute("PRAGMA busy_timeout = 10000;")
    c.row_factory = sqlite3.Row
    return c

def init_db(c):
    c.executescript(SCHEMA)
    # Safe migrations for existing databases
    for col_sql in [
        "ALTER TABLE tokens ADD COLUMN expires_at REAL",
        "ALTER TABLE items ADD COLUMN tags TEXT DEFAULT ''",
        "ALTER TABLE outbox ADD COLUMN created_at REAL DEFAULT 0",
        "ALTER TABLE notifications ADD COLUMN created_at REAL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN created_at REAL DEFAULT 0"
    ]:
        try: c.execute(col_sql)
        except Exception: pass

def hpw(salt, pw): return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 50000).hex()
now = time.time

# ---------- authorization: the ONE permission check, scoped to the item's team ----------
def need(c, uid, team, level):
    r = c.execute("SELECT role FROM memberships WHERE user_id=? AND team_id=?", (uid, team)).fetchone()
    if not r: raise E(404, "not found")  # outsiders cannot even learn the item exists
    if RANK[r[0]] < RANK[level]: raise E(403, f"requires role {level}")

def get_item(c, i):
    r = c.execute("SELECT * FROM items WHERE id=?", (i,)).fetchone()
    if not r: raise E(404, "not found")
    return r

def readable(c, u, i):
    it = get_item(c, i); need(c, u, it["team_id"], "viewer"); return it

def log(c, item, actor, typ, data):  # always called inside the same transaction as the change
    c.execute("INSERT INTO events(item_id,actor_id,type,data,ts) VALUES(?,?,?,?,?)", (item, actor, typ, json.dumps(data), now()))

def enqueue(c, kind, payload):
    c.execute("INSERT INTO outbox(kind,payload,created_at) VALUES(?,?,?)", (kind, json.dumps(payload), now()))

# ---------- handlers ----------
def create(c, u, b, h):
    key = h.get("Idempotency-Key")
    if key:
        r = c.execute("SELECT code,response FROM idem WHERE user_id=? AND key=?", (u, key)).fetchone()
        if r: return r["code"], json.loads(r["response"])
    team = b.get("team_id"); need(c, u, team, "member")
    if not str(b.get("title", "")).strip(): raise E(422, "title required")
    if b.get("priority", "normal") not in PRI or b.get("type", "task") not in TYPES: raise E(422, "bad priority/type")
    cur = c.execute("INSERT INTO items(title,description,type,priority,team_id,created_by,due_date,tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (b["title"].strip(), b.get("description", "").strip(), b.get("type", "task"), b.get("priority", "normal"), team, u, b.get("due_date"), b.get("tags", ""), now(), now()))
    log(c, cur.lastrowid, u, "created", {"title": b["title"]})
    res = dict(get_item(c, cur.lastrowid))
    if key: c.execute("INSERT INTO idem VALUES(?,?,?,?)", (u, key, 201, json.dumps(res)))
    return 201, res

def claim(c, u, i):
    it = get_item(c, i); need(c, u, it["team_id"], "member")
    n = c.execute("UPDATE items SET assignee_id=?,version=version+1,updated_at=? WHERE id=? AND assignee_id IS NULL", (u, now(), i)).rowcount
    if n == 0: raise E(409, "already claimed", {"latest": dict(get_item(c, i))})
    log(c, i, u, "assigned", {"from": None, "to": u}); enqueue(c, "notify_assignee", {"item": i, "user": u})
    return 200, dict(get_item(c, i))

def patch(c, u, i, b):
    it = get_item(c, i); need(c, u, it["team_id"], "member")
    if b.get("version") != it["version"]: raise E(409, "stale version", {"latest": dict(it)})
    sets = {k: b[k] for k in ("title", "description", "priority", "due_date", "tags") if k in b}
    if "assignee_id" in b:
        need(c, u, it["team_id"], "lead")  # reassign = Lead / Admin
        sets["assignee_id"] = b["assignee_id"]
    if not sets: raise E(422, "nothing to update")
    if "priority" in sets and sets["priority"] not in PRI: raise E(422, "bad priority")
    n = c.execute(f"UPDATE items SET {','.join(k+'=?' for k in sets)},version=version+1,updated_at=? WHERE id=? AND version=?",
                  (*sets.values(), now(), i, it["version"])).rowcount
    if n == 0: raise E(409, "stale version", {"latest": dict(get_item(c, i))})
    for k, t in (("priority", "priority_changed"), ("assignee_id", "assigned")):
        if k in sets and sets[k] != it[k]: log(c, i, u, t, {"from": it[k], "to": sets[k]})
    if "assignee_id" in sets and sets["assignee_id"] != it["assignee_id"] and sets["assignee_id"]:
        enqueue(c, "notify_assignee", {"item": i, "user": sets["assignee_id"]})
    return 200, dict(get_item(c, i))

def transition(c, u, i, b):
    it = get_item(c, i); need(c, u, it["team_id"], "member")
    to = b.get("to")
    if "version" in b and b["version"] != it["version"]: raise E(409, "stale version", {"latest": dict(it)})
    if to not in FLOW[it["status"]]: raise E(422, f"{it['status']} -> {to} not allowed")
    if (it["status"], to) in LEAD_ONLY: need(c, u, it["team_id"], "lead")
    c.execute("UPDATE items SET status=?,version=version+1,updated_at=? WHERE id=?", (to, now(), i))
    log(c, i, u, "status_changed", {"from": it["status"], "to": to})
    return 200, dict(get_item(c, i))

def comment(c, u, i, b):
    it = get_item(c, i); need(c, u, it["team_id"], "member")
    text = str(b.get("text", "")).strip()
    if not text: raise E(422, "comment text required")
    log(c, i, u, "comment", {"text": text})
    return 201, {"ok": True}

def list_items(c, u, q):
    g = lambda k: q.get(k, [None])[0]
    where, args = ["team_id IN (SELECT team_id FROM memberships WHERE user_id=?)"], [u]   # server-side scoping
    for k in ("status", "priority", "type", "team_id", "assignee_id"):
        if g(k): where.append(f"{k}=?"); args.append(g(k))
    if g("q"):
        where.append("(title LIKE ? OR description LIKE ? OR tags LIKE ?)")
        args += [f"%{g('q')}%"] * 3
    v = g("view")
    if v == "mine": where.append("assignee_id=? AND status!='closed'"); args.append(u)
    if v == "urgent": where.append("assignee_id IS NULL AND priority='urgent' AND status NOT IN ('resolved','closed')")
    if v == "approval": where.append("status='awaiting_approval' AND team_id IN (SELECT team_id FROM memberships WHERE user_id=? AND role IN ('lead','admin'))"); args.append(u)
    if v == "overdue": where.append("due_date IS NOT NULL AND due_date < date('now') AND status NOT IN ('resolved','closed')")
    if g("cursor"): where.append("id<?"); args.append(int(g("cursor")))
    lim = min(int(g("limit") or 25), 100)
    rows = [dict(r) for r in c.execute(f"SELECT * FROM items WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?", (*args, lim + 1))]
    return 200, {"items": rows[:lim], "next_cursor": rows[lim - 1]["id"] if len(rows) > lim else None}

def export_items(c, u, q):
    res = list_items(c, u, {**q, "limit": ["500"]})[1]
    rows = res["items"]
    fmt = q.get("format", ["json"])[0]
    if fmt == "csv":
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["id", "title", "type", "priority", "status", "team_id", "assignee_id", "due_date", "version", "created_at"])
        for r in rows:
            w.writerow([r["id"], r["title"], r["type"], r["priority"], r["status"], r["team_id"], r["assignee_id"] or "", r.get("due_date") or "", r["version"], r["created_at"]])
        return 200, {"csv": out.getvalue(), "count": len(rows)}
    return 200, {"items": rows, "count": len(rows)}

def route(c, u, m, path, q, b, h):
    # User Profile & Memberships
    if m == "GET" and path == "/me":
        usr = c.execute("SELECT id, name, created_at FROM users WHERE id=?", (u,)).fetchone()
        ms = c.execute("SELECT m.team_id, m.role, t.name as team_name FROM memberships m JOIN teams t ON m.team_id=t.id WHERE m.user_id=?", (u,)).fetchall()
        return 200, {"id": usr["id"], "name": usr["name"], "created_at": usr["created_at"], "memberships": [dict(m) for m in ms]}
    if m == "GET" and path == "/teams":
        return 200, [dict(t) for t in c.execute("SELECT * FROM teams ORDER BY id").fetchall()]
    if m == "GET" and path == "/users":
        return 200, [dict(x) for x in c.execute("SELECT u.id, u.name, m.team_id, m.role FROM users u JOIN memberships m ON u.id=m.user_id ORDER BY u.id").fetchall()]
    if m == "GET" and path == "/notifications":
        return 200, [dict(n) for n in c.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY job_id DESC LIMIT 40", (u,)).fetchall()]
    if m == "GET" and path == "/export":
        return export_items(c, u, q)
    if m == "POST" and path == "/users/password":
        old_pw = b.get("current_password", "")
        new_pw = b.get("new_password", "")
        if len(new_pw) < 6: raise E(422, "new password must be at least 6 characters")
        usr = c.execute("SELECT salt, pw FROM users WHERE id=?", (u,)).fetchone()
        if hpw(usr["salt"], old_pw) != usr["pw"]: raise E(401, "incorrect current password")
        new_salt = secrets.token_hex(4)
        c.execute("UPDATE users SET salt=?, pw=? WHERE id=?", (new_salt, hpw(new_salt, new_pw), u))
        return 200, {"ok": True, "message": "password updated successfully"}

    # Admin dead-letter queue inspection & retries
    if m == "GET" and path == "/admin/outbox":
        need(c, u, 1, "admin")
        return 200, [dict(r) for r in c.execute("SELECT * FROM outbox ORDER BY id DESC LIMIT 50").fetchall()]
    m_retry = re.fullmatch(r"/admin/outbox/(\d+)/retry", path)
    if m == "POST" and m_retry:
        need(c, u, 1, "admin")
        jid = int(m_retry[1])
        c.execute("UPDATE outbox SET status='pending', attempts=0, next_run=? WHERE id=?", (now(), jid))
        return 200, {"ok": True, "job_id": jid, "status": "pending"}

    # Core Work-Item Routes
    if m == "GET" and path == "/items": return list_items(c, u, q)
    if m == "POST" and path == "/items": return create(c, u, b, h)
    r = re.fullmatch(r"/items/(\d+)(?:/(\w+))?", path)
    if r:
        i, act = int(r[1]), r[2]
        if m == "GET" and not act: return 200, dict(readable(c, u, i))
        if m == "GET" and act == "activity":
            readable(c, u, i); return 200, [dict(e) for e in c.execute("SELECT * FROM events WHERE item_id=? ORDER BY id", (i,))]
        if m == "PATCH" and not act: return patch(c, u, i, b)
        if m == "POST" and act == "claim": return claim(c, u, i)
        if m == "POST" and act == "transition": return transition(c, u, i, b)
        if m == "POST" and act == "comments": return comment(c, u, i, b)
    raise E(404, "no such route")

# ---------- async worker (transactional outbox, retries w/ backoff, idempotent handler) ----------
def notify(c, job):
    p = json.loads(job["payload"])
    # UNIQUE(job_id) + OR IGNORE => processing twice yields one notification
    c.execute("INSERT OR IGNORE INTO notifications(job_id,user_id,message,created_at) VALUES(?,?,?,?)",
              (job["id"], p["user"], f"You were assigned item #{p['item']}", now()))

def process_outbox(handler=notify, max_attempts=3, at=None):
    c = db(); at = now() if at is None else at; done = 0
    for job in c.execute("SELECT * FROM outbox WHERE status='pending' AND next_run<=?", (at,)).fetchall():
        try:
            c.execute("BEGIN IMMEDIATE"); handler(c, job)
            c.execute("UPDATE outbox SET status='done' WHERE id=?", (job["id"],)); c.execute("COMMIT"); done += 1
        except Exception:
            c.execute("ROLLBACK"); a = job["attempts"] + 1
            c.execute("UPDATE outbox SET attempts=?,status=?,next_run=? WHERE id=?", (a, "failed" if a >= max_attempts else "pending", now() + 2 ** a, job["id"]))
    return done

# ---------- HTTP ----------
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj, ctype="application/json"):
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Idempotency-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send(204, b"")

    def handle_any(self):
        url = urlparse(self.path)
        # Static asset serving
        if self.command == "GET" and url.path in ("/", "/index.html"):
            for p in (os.path.join(os.path.dirname(__file__), "static", "index.html"),
                      os.path.join(os.path.dirname(__file__), "index.html")):
                if os.path.exists(p):
                    with open(p, "rb") as f:
                        return self.send(200, f.read(), "text/html")
            return self.send(404, {"error": "index.html not found"})

        # Production Health Check
        if self.command == "GET" and url.path == "/health":
            try:
                c = db()
                total_items = c.execute("SELECT COUNT(*) FROM items").fetchone()[0]
                pending_jobs = c.execute("SELECT COUNT(*) FROM outbox WHERE status='pending'").fetchone()[0]
                failed_jobs = c.execute("SELECT COUNT(*) FROM outbox WHERE status='failed'").fetchone()[0]
                return self.send(200, {
                    "status": "healthy",
                    "version": "2.0.0-production",
                    "uptime_seconds": round(now() - SERVER_START_TIME, 1),
                    "database": {"engine": "SQLite WAL", "total_items": total_items},
                    "outbox": {"pending_jobs": pending_jobs, "failed_jobs": failed_jobs}
                })
            except Exception as e:
                return self.send(503, {"status": "unhealthy", "error": str(e)})

        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            c = db()

            # Public Registration
            if url.path == "/register" and self.command == "POST":
                name = str(body.get("username", "")).strip()
                pw = str(body.get("password", ""))
                if not name or len(pw) < 6: raise E(422, "username required and password must be >= 6 chars")
                if c.execute("SELECT 1 FROM users WHERE name=?", (name,)).fetchone(): raise E(409, "username already exists")
                salt = secrets.token_hex(4)
                cur = c.execute("INSERT INTO users(name, salt, pw, created_at) VALUES(?,?,?,?)", (name, salt, hpw(salt, pw), now()))
                new_uid = cur.lastrowid
                team_id = int(body.get("team_id", 1))
                role = body.get("role", "member")
                if role not in RANK: role = "member"
                c.execute("INSERT INTO memberships VALUES(?,?,?)", (new_uid, team_id, role))
                t = secrets.token_hex(24)
                exp = now() + TOKEN_TTL
                c.execute("INSERT INTO tokens(token, user_id, expires_at) VALUES(?,?,?)", (t, new_uid, exp))
                return self.send(201, {"token": t, "user_id": new_uid, "username": name, "team_id": team_id, "role": role})

            # Authentication / Login
            if url.path == "/login" and self.command == "POST":
                r = c.execute("SELECT * FROM users WHERE name=?", (body.get("username"),)).fetchone()
                if not r or hpw(r["salt"], body.get("password", "")) != r["pw"]: raise E(401, "bad credentials")
                t = secrets.token_hex(24)
                exp = now() + TOKEN_TTL
                c.execute("INSERT INTO tokens(token, user_id, expires_at) VALUES(?,?,?)", (t, r["id"], exp))
                return self.send(200, {"token": t, "user_id": r["id"], "username": r["name"], "expires_at": exp})

            # Authenticated Bearer Token Check
            tk = (self.headers.get("Authorization") or "").replace("Bearer ", "")
            r = c.execute("SELECT user_id, expires_at FROM tokens WHERE token=?", (tk,)).fetchone()
            if not r: raise E(401, "login required")
            if r["expires_at"] and r["expires_at"] < now():
                c.execute("DELETE FROM tokens WHERE token=?", (tk,))
                raise E(401, "session expired")

            # Logout
            if url.path == "/logout" and self.command == "POST":
                c.execute("DELETE FROM tokens WHERE token=?", (tk,))
                return self.send(200, {"ok": True, "message": "logged out successfully"})

            # One transaction per request: state change + event + outbox commit together
            c.execute("BEGIN IMMEDIATE")
            try:
                code, res = route(c, r[0], self.command, url.path, parse_qs(url.query), body, self.headers)
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK"); raise
            self.send(code, res)
        except E as e: self.send(e.code, {"error": e.msg, **e.extra})
        except (ValueError, KeyError, TypeError) as e: self.send(400, {"error": f"bad request: {e}"})

    do_GET = do_POST = do_PATCH = handle_any

def serve(port=8000):
    import threading
    init_db(db())
    def loop():
        while True:
            try: process_outbox()
            except Exception: pass
            time.sleep(2)
    threading.Thread(target=loop, daemon=True).start()
    s = ThreadingHTTPServer(("0.0.0.0", port), H)
    print("Operations Under Pressure Production Server: http://localhost:%d" % port)
    return s

def seed(n_items=5000):
    c = db()
    init_db(c)
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]: return
    c.execute("BEGIN TRANSACTION")
    teams = ["Payments", "Support", "Compliance"]
    for t in teams: c.execute("INSERT INTO teams(name) VALUES(?)", (t,))
    users = {
        "alice": [(1, "admin"), (2, "admin"), (3, "admin")],
        "bob": [(1, "lead")],
        "carol": [(1, "member")],
        "dave": [(1, "viewer")],
        "erin": [(2, "lead")],
        "frank": [(2, "member")],
        "gina": [(3, "member"), (2, "viewer")],
        "hank": [(3, "lead")]
    }
    for i, (name, ms) in enumerate(users.items(), 1):
        salt = secrets.token_hex(4)
        c.execute("INSERT INTO users(id, name, salt, pw, created_at) VALUES(?,?,?,?,?)", (i, name, salt, hpw(salt, "password123"), now()))
        c.executemany("INSERT INTO memberships VALUES(?,?,?)", [(i, t, r) for t, r in ms])
    st = list(FLOW); rows = []
    actions = [
        "Payment webhook timeout on Stripe gateway",
        "High CPU utilization in auth cluster",
        "PCI-DSS audit compliance verification required",
        "Merchant chargeback escalation #8491",
        "Database read replica replication lag > 500ms",
        "API rate limit exceeded for enterprise tenant",
        "Fraud detection false-positive surge in EU region",
        "Automated KYC document verification failure"
    ]
    for k in range(n_items):
        t = random.randint(1, 3); s = random.choice(st)
        assignee = random.choice([None, None, 2, 5]) if t in (1, 2) else None
        rows.append((
            f"Item #{k}: {random.choice(actions)}",
            random.choice(TYPES),
            random.choice(PRI),
            s,
            t,
            assignee,
            1,
            now(),
            now()
        ))
    c.executemany("INSERT INTO items(title,type,priority,status,team_id,assignee_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", rows)
    c.execute("COMMIT")
    print(f"Successfully seeded {n_items} production work items.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "seed": seed()
    else:
        seed()
        port = int(os.environ.get("PORT", 8000))
        serve(port).serve_forever()
