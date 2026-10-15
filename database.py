import aiosqlite
from datetime import datetime, timedelta, timezone
from config import DATABASE_PATH, FREE_TOKENS, RESET_HOURS

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt=None):
    return (dt or now_utc()).isoformat()

def parse_dt(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None

async def init_db():
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT,
            is_pro INTEGER DEFAULT 0, pro_until TEXT, tokens INTEGER DEFAULT 3,
            last_reset TEXT, total_lookups INTEGER DEFAULT 0,
            joined_date TEXT, is_banned INTEGER DEFAULT 0
        )""")
        await db.execute("""
        CREATE TABLE IF NOT EXISTS usage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            domain TEXT NOT NULL, timestamp TEXT NOT NULL, success INTEGER NOT NULL
        )""")
        await db.execute("""
        CREATE TABLE IF NOT EXISTS failed_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            domain TEXT NOT NULL, error TEXT NOT NULL, timestamp TEXT NOT NULL
        )""")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_usage_user_time ON usage_log(user_id, timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_failed_user ON failed_log(user_id)")
        await db.commit()

async def create_user(user_id, username=None, first_name=None):
    now = iso()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
        INSERT INTO users(user_id, username, first_name, tokens, last_reset, joined_date)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, first_name=excluded.first_name
        """, (user_id, username, first_name, FREE_TOKENS, now, now))
        await db.commit()
    return await get_user(user_id)

async def get_user(user_id):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

async def reset_tokens_if_needed(user_id):
    now = now_utc()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("BEGIN IMMEDIATE")
        cur = await db.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
        row = await cur.fetchone()
        if not row:
            await db.execute("""
                INSERT INTO users(user_id,tokens,last_reset,joined_date) VALUES(?,?,?,?)
            """, (user_id, FREE_TOKENS, iso(now), iso(now)))
            await db.commit()
            return await get_user(user_id)
        last = parse_dt(row["last_reset"])
        if last is None or now - last >= timedelta(hours=RESET_HOURS):
            await db.execute("UPDATE users SET tokens=?, last_reset=? WHERE user_id=?",
                             (FREE_TOKENS, iso(now), user_id))
        # Expire pro automatically when its timestamp has passed.
        pro_until = parse_dt(row["pro_until"])
        if row["is_pro"] and pro_until and now >= pro_until:
            await db.execute("UPDATE users SET is_pro=0 WHERE user_id=?", (user_id,))
        await db.commit()
    return await get_user(user_id)

async def can_search_and_get_tokens(user_id):
    user = await reset_tokens_if_needed(user_id)
    if not user:
        return {"allowed": False, "reason": "User record unavailable.", "user": None}
    if user["is_banned"]:
        return {"allowed": False, "reason": "Your account is banned.", "user": user}
    pro_until = parse_dt(user.get("pro_until"))
    is_pro = bool(user["is_pro"]) and (pro_until is None or now_utc() < pro_until)
    if is_pro:
        return {"allowed": True, "pro": True, "tokens": user["tokens"], "user": user}
    if user["tokens"] <= 0:
        last = parse_dt(user.get("last_reset")) or now_utc()
        reset_at = last + timedelta(hours=RESET_HOURS)
        remaining = max(0, int((reset_at - now_utc()).total_seconds()))
        return {"allowed": False, "reason": "no_tokens", "tokens": 0,
                "seconds_left": remaining, "user": user}
    return {"allowed": True, "pro": False, "tokens": user["tokens"], "user": user}

async def use_token(user_id, success=True, domain=None):
    """Atomically charge only a successful lookup; returns the refreshed user."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("BEGIN IMMEDIATE")
        cur = await db.execute("SELECT is_pro, pro_until, tokens FROM users WHERE user_id=?", (user_id,))
        row = await cur.fetchone()
        if row:
            is_pro, pro_until, tokens = row
            until = parse_dt(pro_until)
            pro_active = bool(is_pro) and (until is None or now_utc() < until)
            if success:
                if not pro_active:
                    if tokens <= 0:
                        await db.rollback()
                        return await get_user(user_id)
                    await db.execute("UPDATE users SET tokens=tokens-1 WHERE user_id=?", (user_id,))
                await db.execute("UPDATE users SET total_lookups=total_lookups+1 WHERE user_id=?", (user_id,))
                await db.execute("INSERT INTO usage_log(user_id,domain,timestamp,success) VALUES(?,?,?,1)",
                                 (user_id, domain or "", iso()))
        await db.commit()
    return await get_user(user_id)

async def log_usage(user_id, domain, success=True):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("INSERT INTO usage_log(user_id,domain,timestamp,success) VALUES(?,?,?,?)",
                         (user_id, domain, iso(), int(success)))
        await db.commit()

async def log_failed(user_id, domain, error):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("INSERT INTO failed_log(user_id,domain,error,timestamp) VALUES(?,?,?,?)",
                         (user_id, domain, str(error)[:1000], iso()))
        await db.commit()

async def add_pro(user_id, days):
    user = await get_user(user_id)
    if not user:
        await create_user(user_id)
        user = await get_user(user_id)
    current = parse_dt(user.get("pro_until"))
    start = max(now_utc(), current) if current else now_utc()
    until = start + timedelta(days=days)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("UPDATE users SET is_pro=1, pro_until=? WHERE user_id=?", (iso(until), user_id))
        await db.commit()
    return until

async def remove_pro(user_id):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("UPDATE users SET is_pro=0, pro_until=NULL WHERE user_id=?", (user_id,))
        await db.commit()

async def adjust_tokens(user_id, amount, exact=False):
    if not await get_user(user_id):
        await create_user(user_id)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        if exact:
            await db.execute("UPDATE users SET tokens=? WHERE user_id=?", (max(0, amount), user_id))
        else:
            await db.execute("UPDATE users SET tokens=MAX(0,tokens+?) WHERE user_id=?", (amount, user_id))
        await db.commit()
    return await get_user(user_id)

async def set_banned(user_id, banned):
    if not await get_user(user_id):
        await create_user(user_id)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("UPDATE users SET is_banned=? WHERE user_id=?", (int(banned), user_id))
        await db.commit()

async def get_history(user_id, limit=10):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT domain,timestamp FROM usage_log WHERE user_id=? AND success=1 ORDER BY id DESC LIMIT ?",
                               (user_id, limit))
        return [dict(r) for r in await cur.fetchall()]

async def get_stats():
    today = iso(now_utc().replace(hour=0, minute=0, second=0, microsecond=0))
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM users")
        users = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE is_pro=1 AND (pro_until IS NULL OR pro_until>?)", (iso(),))
        pro = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM usage_log WHERE success=1")
        successful = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM failed_log")
        failed = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM users WHERE joined_date>=?", (today,))
        active_today = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM usage_log WHERE timestamp>=? AND success=1", (today,))
        tokens_used = (await cur.fetchone())[0]
    return {"users": users, "pro": pro, "free": users-pro, "successful": successful,
            "failed": failed, "active_today": active_today, "tokens_used_today": tokens_used}

async def get_all_user_ids():
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cur = await db.execute("SELECT user_id FROM users WHERE is_banned=0")
        return [r[0] for r in await cur.fetchall()]

async def get_user_admin_info(user_id):
    user = await get_user(user_id)
    if not user:
        return None
    user["history"] = await get_history(user_id, 10)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM failed_log WHERE user_id=?", (user_id,))
        user["failed_count"] = (await cur.fetchone())[0]
    return user
