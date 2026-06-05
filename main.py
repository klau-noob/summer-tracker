import os
import sqlite3
import secrets
import time
from contextlib import contextmanager
from pathlib import Path

from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DB_PATH = Path(os.getenv("DB_PATH", "data/tracker.db"))
PORT = int(os.getenv("PORT", 8000))
PARENT_PIN = os.getenv("PARENT_PIN", "")
KID_PIN = os.getenv("KID_PIN", "")

DEFAULT_TASKS = [
    "2 Duolingo Spanish lessons",
    "Khan Academy (30 min)",
    "Reading (20–30 min or 20 pages)",
    "AI Game Project (20 min)",
    "30 min physical activity",
    "Household responsibility",
]

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def db():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tracker_data (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        # Seed default tasks if empty
        count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        if count == 0:
            for i, name in enumerate(DEFAULT_TASKS):
                conn.execute(
                    "INSERT INTO tasks (name, active, sort_order) VALUES (?, 1, ?)",
                    (name, i),
                )


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

SESSION_TTL = 60 * 60 * 24 * 30  # 30 days


def create_session(role: str) -> str:
    token = secrets.token_hex(32)
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, role, created_at) VALUES (?, ?, ?)",
            (token, role, int(time.time())),
        )
    return token


def validate_session(token: str, role: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT role, created_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
    if not row:
        return False
    if row["role"] != role:
        return False
    if int(time.time()) - row["created_at"] > SESSION_TTL:
        return False
    return True


def require_auth(
    x_session_token: str = Header(default=""),
    x_role: str = Header(default=""),
):
    if not validate_session(x_session_token, x_role):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return x_role


def require_parent(role: str = Depends(require_auth)):
    if role != "parent":
        raise HTTPException(status_code=403, detail="Parent access required")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI()
init_db()


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

class AuthRequest(BaseModel):
    role: str
    pin: str


@app.post("/auth")
def auth(req: AuthRequest):
    if req.role == "parent":
        expected = PARENT_PIN
    elif req.role == "kid":
        expected = KID_PIN
    else:
        raise HTTPException(status_code=400, detail="Invalid role")

    if not expected:
        raise HTTPException(status_code=500, detail=f"{req.role.upper()}_PIN not set")
    if req.pin != expected:
        raise HTTPException(status_code=401, detail="Incorrect PIN")

    token = create_session(req.role)
    return {"token": token, "role": req.role}


@app.post("/auth/verify")
def verify_session(role: str = Depends(require_auth)):
    return {"valid": True, "role": role}


# ---------------------------------------------------------------------------
# Task routes
# ---------------------------------------------------------------------------

class TaskCreate(BaseModel):
    name: str


class TaskUpdate(BaseModel):
    name: Optional[str] = None
    active: Optional[bool] = None


@app.get("/tasks")
def list_tasks(role: str = Depends(require_auth)):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, active, sort_order FROM tasks ORDER BY sort_order, id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/tasks", dependencies=[Depends(require_parent)])
def create_task(body: TaskCreate):
    with db() as conn:
        max_order = conn.execute("SELECT COALESCE(MAX(sort_order),0) FROM tasks").fetchone()[0]
        cur = conn.execute(
            "INSERT INTO tasks (name, active, sort_order) VALUES (?, 1, ?) RETURNING id, name, active, sort_order",
            (body.name.strip(), max_order + 1),
        )
        row = cur.fetchone()
    return dict(row)


@app.put("/tasks/{task_id}", dependencies=[Depends(require_parent)])
def update_task(task_id: int, body: TaskUpdate):
    with db() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")
        new_name = body.name.strip() if body.name is not None else row["name"]
        new_active = int(body.active) if body.active is not None else row["active"]
        conn.execute(
            "UPDATE tasks SET name = ?, active = ? WHERE id = ?",
            (new_name, new_active, task_id),
        )
        updated = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    return dict(updated)


@app.delete("/tasks/{task_id}", dependencies=[Depends(require_parent)])
def delete_task(task_id: int):
    with db() as conn:
        row = conn.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found")
        conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    return {"deleted": task_id}


# ---------------------------------------------------------------------------
# Tracker data routes
# ---------------------------------------------------------------------------

class DataPayload(BaseModel):
    state: dict


@app.get("/data")
def get_data(role: str = Depends(require_auth)):
    import json
    with db() as conn:
        row = conn.execute(
            "SELECT value FROM tracker_data WHERE key = 'state'"
        ).fetchone()
    if not row:
        return {"state": {}}
    return {"state": json.loads(row["value"])}


@app.post("/data")
def save_data(body: DataPayload, role: str = Depends(require_auth)):
    import json
    with db() as conn:
        conn.execute(
            "INSERT INTO tracker_data (key, value) VALUES ('state', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (json.dumps(body.state),),
        )
    return {"ok": True}


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
