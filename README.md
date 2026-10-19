# Operations Under Pressure — Enterprise Edition

Mission-critical internal web application to create, assign, track, and resolve operational incidents and work items across cross-functional engineering teams. Features team-scoped RBAC (`viewer`/`member`/`lead`/`admin`), server-enforced workflow state machine, append-only activity audit stream, keyset cursor pagination, SQLite WAL mode, token expiry & session revocation, dead-letter queue (DLQ) retry worker, CSV/JSON auditing export, and real-time outbox notifications.

## 🚀 Quick Run (Python 3.9+, Zero External Dependencies)

```bash
# 1. Start Production Server (Seeds 5,000 items on first run, serves http://localhost:8000)
python app.py

# 2. Run Comprehensive Automated Test Suite (All 9 tests pass in < 0.7s)
python -m unittest test_app -v

# 3. Docker deployment
docker compose up
```

## 🔐 Authentication & Demo Personas

The system features real enterprise token authentication (with 24h configurable TTL, session expiration, and `/logout` revocation) plus account registration and password changing.

For testing and verification, an interactive **Role Simulator** is embedded in the UI:
- **alice**: Admin (All teams: Payments, Support, Compliance)
- **bob**: Lead (Payments)
- **carol**: Member (Payments)
- **dave**: Viewer (Payments)
- **erin**: Lead (Support)
- **frank**: Member (Support)
- **gina**: Member (Compliance), Viewer (Support)
- **hank**: Lead (Compliance)
*(Default seed password for all personas: `password123`)*

## 🌐 Complete REST API Reference

| Endpoint | Method | Role / Auth | Description |
| :--- | :---: | :---: | :--- |
| `/health` | `GET` | Public | System status, database engine, uptime, and outbox metrics |
| `/login` | `POST` | Public | Authenticates operator, generates bearer token with TTL |
| `/register` | `POST` | Public / Admin | Registers a new operator account and assigns team/role |
| `/logout` | `POST` | Authenticated | Revokes current token immediately |
| `/me` | `GET` | Authenticated | Current user profile, teams, and scoped role permissions |
| `/teams` | `GET` | Authenticated | List all operational teams |
| `/users` | `GET` | Authenticated | List team users for assignment & reassignment |
| `/users/password` | `POST` | Authenticated | Updates current operator password securely |
| `/items` | `GET` | Authenticated | Scoped work-item list (filters: `status`, `priority`, `type`, `team_id`, `assignee_id`, `view`, `q`, `limit`, `cursor`) |
| `/items` | `POST` | Member+ | Creates new work item with atomic transaction and `Idempotency-Key` |
| `/items/:id` | `GET` | Viewer+ | Retrieves single item (404 for unpermitted teams) |
| `/items/:id` | `PATCH` | Member+ / Lead+ | Edits item fields with optimistic concurrency version check |
| `/items/:id/claim` | `POST` | Member+ | Atomic claim: `WHERE assignee_id IS NULL` (409 on conflict) |
| `/items/:id/transition` | `POST` | Member+ / Lead+ | Advances workflow state (`awaiting_approval` -> `resolved` requires Lead) |
| `/items/:id/comments` | `POST` | Member+ | Appends comment to immutable event stream |
| `/items/:id/activity` | `GET` | Viewer+ | Full chronological audit trail of item events |
| `/export` | `GET` | Authenticated | Exports filtered work items as CSV or JSON for compliance |
| `/notifications` | `GET` | Authenticated | Outbox notifications delivered to the active operator |
| `/admin/outbox` | `GET` | Admin | Dead-letter queue (DLQ) inspection of pending and failed jobs |
| `/admin/outbox/:id/retry` | `POST` | Admin | Manually resets a failed job back to pending |

## 🛡️ Core Production Behaviors (Verified by Unit Tests)

1. **Atomic Claiming**: Zero-row update on already assigned items returns `409 Conflict`.
2. **Optimistic Concurrency**: Edits verify `WHERE version = ?`. Stale edits return `409 Conflict` with latest data.
3. **Idempotency Keys**: Network retries with duplicate `Idempotency-Key` headers return identical responses without duplicate records.
4. **Workflow State Machine**: Strictly validates transitions:
   - `open` ➔ `in_progress` ➔ `awaiting_approval` ➔ `resolved` ➔ `closed`.
   - `awaiting_approval` ➔ `resolved` requires Team Lead or Admin role.
5. **Team-Scoped Authorization**: Scoped SQL queries prevent leakage. Non-members receive `404 Not Found`.
6. **Transactional Outbox Worker**: Enqueues notification jobs inside the same DB transaction. Retries failed jobs with exponential backoff (`2^attempts` seconds) up to 3 times before marking as failed. Idempotent handler guarantees exactly-once notification delivery.
7. **SQLite WAL Mode & High Concurrency**: `PRAGMA journal_mode = WAL;` enables non-blocking concurrent reads and writes with a 10s busy timeout.
