import os, tempfile, threading, json, unittest, urllib.request, urllib.error
os.environ["DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app

def call(m, p, tok=None, body=None, hdr=None):
    h = {"Content-Type": "application/json", **(hdr or {})}
    if tok: h["Authorization"] = "Bearer " + tok
    rq = urllib.request.Request(f"http://127.0.0.1:{PORT}{p}", method=m, headers=h, data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(rq) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e: return e.code, json.load(e)

def login(u): return call("POST", "/login", body={"username": u, "password": "password123"})[1]["token"]

class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global PORT
        app.seed(30); s = app.serve(0); PORT = s.server_address[1]
        threading.Thread(target=s.serve_forever, daemon=True).start()
        cls.bob, cls.carol, cls.dave, cls.erin = map(login, ["bob", "carol", "dave", "erin"])

    def new(self, **kw):
        return call("POST", "/items", self.carol, {"title": "t", "team_id": 1, **kw})[1]["id"]

    def test_concurrent_claim_only_one_wins(self):
        i = self.new(); out = []
        def go(tok): out.append(call("POST", f"/items/{i}/claim", tok)[0])
        ts = [threading.Thread(target=go, args=(t,)) for t in (self.bob, self.carol)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(sorted(out), [200, 409])

    def test_stale_update_rejected_data_unchanged(self):
        i = self.new(); it = call("GET", f"/items/{i}", self.carol)[1]
        self.assertEqual(call("PATCH", f"/items/{i}", self.carol, {"version": it["version"], "priority": "high"})[0], 200)
        c, r = call("PATCH", f"/items/{i}", self.carol, {"version": it["version"], "priority": "low"})
        self.assertEqual(c, 409); self.assertEqual(r["latest"]["priority"], "high")

    def test_idempotency_key_creates_one(self):
        k = {"Idempotency-Key": "abc-123"}; body = {"title": "dup", "team_id": 1}
        a = call("POST", "/items", self.carol, body, k); b = call("POST", "/items", self.carol, body, k)
        self.assertEqual(a, b); n = [x for x in call("GET", "/items?q=dup", self.carol)[1]["items"]]
        self.assertEqual(len(n), 1)

    def test_workflow_rules(self):
        i = self.new()
        self.assertEqual(call("POST", f"/items/{i}/transition", self.carol, {"to": "closed"})[0], 422)
        for s in ("in_progress", "awaiting_approval"): call("POST", f"/items/{i}/transition", self.carol, {"to": s})
        self.assertEqual(call("POST", f"/items/{i}/transition", self.carol, {"to": "resolved"})[0], 403)  # member can't approve
        self.assertEqual(call("POST", f"/items/{i}/transition", self.bob, {"to": "resolved"})[0], 200)    # lead can
        ev = [e["type"] for e in call("GET", f"/items/{i}/activity", self.bob)[1]]
        self.assertEqual(ev, ["created"] + ["status_changed"] * 3)

    def test_authorization(self):
        i = self.new()
        self.assertEqual(call("GET", f"/items/{i}", self.erin)[0], 404)                       # other team: no read
        self.assertEqual(call("POST", f"/items/{i}/claim", self.erin)[0], 404)                # no write
        self.assertEqual(call("POST", f"/items/{i}/claim", self.dave)[0], 403)                # viewer can't write
        self.assertTrue(all(x["team_id"] == 2 for x in call("GET", "/items", self.erin)[1]["items"] if x["team_id"] != 2 or True))
        self.assertNotIn(1, {x["team_id"] for x in call("GET", "/items?limit=100", self.erin)[1]["items"]})

    def test_pagination(self):
        a = call("GET", "/items?limit=5", self.bob)[1]; b = call("GET", f"/items?limit=5&cursor={a['next_cursor']}", self.bob)[1]
        self.assertFalse({x["id"] for x in a["items"]} & {x["id"] for x in b["items"]})

    def test_outbox_idempotent_and_retry_then_fail(self):
        i = self.new(); call("POST", f"/items/{i}/claim", self.bob)
        app.process_outbox(at=float("inf")); app.process_outbox(at=float("inf"))
        c = app.db(); self.assertEqual(c.execute("SELECT COUNT(*) FROM notifications WHERE message LIKE ?", (f"%#{i}",)).fetchone()[0], 1)
        c.execute("INSERT INTO outbox(kind,payload) VALUES('x','{}')")
        def boom(c, j): raise RuntimeError
        for _ in range(3): app.process_outbox(boom, 3, at=float("inf"))
        self.assertEqual(c.execute("SELECT status FROM outbox ORDER BY id DESC LIMIT 1").fetchone()[0], "failed")

    def test_ui_and_helper_endpoints(self):
        code, content = call("GET", "/login") # without method shouldn't fail GET /
        rq = urllib.request.Request(f"http://127.0.0.1:{PORT}/")
        with urllib.request.urlopen(rq) as r:
            self.assertEqual(r.status, 200)
            self.assertIn(b"Operations Under Pressure", r.read())
        c, me = call("GET", "/me", self.carol)
        self.assertEqual(c, 200); self.assertEqual(me["name"], "carol")
        c, teams = call("GET", "/teams", self.carol)
        self.assertEqual(c, 200); self.assertTrue(len(teams) >= 3)
        c, notifs = call("GET", "/notifications", self.bob)
        self.assertEqual(c, 200); self.assertIsInstance(notifs, list)

    def test_production_features(self):
        # Health check
        rq = urllib.request.Request(f"http://127.0.0.1:{PORT}/health")
        with urllib.request.urlopen(rq) as r:
            self.assertEqual(r.status, 200)
            data = json.load(r)
            self.assertEqual(data["status"], "healthy")
            self.assertIn("uptime_seconds", data)

        # Export CSV
        c, exp = call("GET", "/export?format=csv", self.carol)
        self.assertEqual(c, 200)
        self.assertIn("csv", exp)
        self.assertIn("title", exp["csv"])

        # User Registration
        c, reg = call("POST", "/register", body={"username": "zack_test", "password": "password123", "team_id": 1, "role": "member"})
        self.assertEqual(c, 201)
        zack_tok = reg["token"]
        c, me = call("GET", "/me", zack_tok)
        self.assertEqual(c, 200)
        self.assertEqual(me["name"], "zack_test")

        # Password update
        c, p_res = call("POST", "/users/password", zack_tok, {"current_password": "password123", "new_password": "newpassword456"})
        self.assertEqual(c, 200)

        # Logout & token invalidation
        c, lo = call("POST", "/logout", zack_tok)
        self.assertEqual(c, 200)
        c, me_after = call("GET", "/me", zack_tok)
        self.assertEqual(c, 401)  # Token was revoked

if __name__ == "__main__": unittest.main()
