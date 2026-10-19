# Engineering Decisions (Production Edition)

## Assumptions & State Machine
Work-item workflow: `open` ➔ `in_progress` ➔ `awaiting_approval` ➔ `resolved` ➔ `closed` (+ allowed back-transitions).
- A member can claim only unassigned items.
- Only a Team Lead or Admin can approve (`awaiting_approval` ➔ `resolved` or back to `in_progress`).
- Reassigning work items requires Team Lead or Admin privilege.

## Architectural Trade-offs & Production Upgrades

1. **Stack & Zero Dependencies:**
   - **Choice:** Standard library Python 3.9+ and SQLite. Runs anywhere out-of-the-box on Windows, Linux, and macOS without virtualenv overhead or external package build issues.
   - **Upgrade:** Enabled SQLite **WAL Mode** (`PRAGMA journal_mode = WAL;`) and `PRAGMA synchronous = NORMAL;`. This allows non-blocking concurrent reads while writes occur in parallel, raising throughput significantly.

2. **Concurrency & Locking:**
   - **Atomic Claiming:** `UPDATE items SET assignee_id = ? ... WHERE id = ? AND assignee_id IS NULL`. Zero rows affected immediately raises `409 Conflict`.
   - **Optimistic Concurrency:** Edits and transitions enforce `WHERE version = ?` and increment `version = version + 1`. Version mismatch immediately returns `409 Conflict` with the latest record payload so clients can reconcile.
   - **Transaction Isolation:** Each HTTP request runs inside a dedicated `BEGIN IMMEDIATE` transaction ensuring state change, event audit row, and outbox notification row commit atomically.

3. **Authorization & RBAC:**
   - Single server-enforced `need(c, uid, team, level)` gatekeeper.
   - List queries are filtered at the database level by membership (`team_id IN (SELECT team_id FROM memberships WHERE user_id = ?)`). Non-members receive `404 Not Found` to prevent information disclosure. Insufficient privilege returns `403 Forbidden`.

4. **Security & Session Management:**
   - PBKDF2-HMAC-SHA256 password hashing with unique per-user salts.
   - Tokens now include configurable TTL expiry (default 24 hours), session validation, and instant revocation via `POST /logout`.
   - Operators can register accounts or update passwords via authenticated endpoints.

5. **Audit Trail & Async Outbox:**
   - Immutable, append-only `events` table records every lifecycle event (`created`, `assigned`, `status_changed`, `priority_changed`, `comment`).
   - Transactional outbox enqueues jobs in the same transaction as the change. Background worker retries with exponential backoff (`2^attempts` seconds) up to 3 times before routing to the Dead-Letter Queue (`status = 'failed'`).
   - Handler enforces `INSERT OR IGNORE` with `UNIQUE(job_id)` to guarantee exactly-once processing.
   - Admin DLQ inspection and retry endpoints (`GET /admin/outbox` and `POST /admin/outbox/:id/retry`).

6. **Keyset Pagination:**
   - Fast keyset cursor pagination (`id < cursor ORDER BY id DESC LIMIT ?`), preventing the `O(N)` performance penalty of deep `OFFSET` pagination.
