# Domain WHOIS + DNS Lookup Bot — Jazib Ali Abbas Edition

A Python 3.11+ Telegram bot with WHOIS/RDAP fallback, DNS records, token accounting, PRO membership, PDF exports, domain monitoring, admin tools, and SQLite backups. Branding: **Powered by Jazib Ali Abbas**.

## What's new in this upgrade

- `/profile` and `/mystats` — account plan, tokens, lookup totals, seven-day usage, failed attempts, and watchlist count.
- `/watch domain.com`, `/unwatch domain.com`, `/watchlist` — daily best-effort DNS change and domain-expiry milestone alerts.
- DNS records expanded to NS, A, AAAA, CNAME, MX, and TXT.
- Admin `/backup` — creates and sends a consistent SQLite backup privately to the admin.
- Automatic daily database backups in `BACKUP_DIR`, with retention cleanup.
- Admin dashboard statistics include watched domains.
- Branded PDF export includes registration data, DNS records, requester, membership tier, and generation time.
- Database changes are additive: the existing `users`, `usage_log`, and `failed_log` tables are preserved. A new `domain_watches` table is created on startup.

## FadeHost deployment / update

1. **Stop the current bot process first** so two processes do not poll Telegram or write to the same SQLite file.
2. Back up your current `bot.db` (download it from the host if possible). Keep a copy somewhere private.
3. Upload/replace the project files with the files in this ZIP. Keep your existing `.env` or hosting environment variables; do not overwrite your token or admin IDs.
4. Confirm these variables are still configured in FadeHost:
   - `BOT_TOKEN` — your existing BotFather token
   - `ADMIN_IDS` — your numeric Telegram user ID(s), comma-separated
   - `DATABASE_PATH` — **the exact path to your existing database**. Do not change it during an upgrade.
5. Install dependencies from `requirements.txt` (especially `python-telegram-bot[job-queue]` and `reportlab`).
6. Start command: `python main.py`.
7. Open the bot and test `/start`, `/profile`, `/mystats`, a lookup such as `example.com`, and PDF export. Then test `/watch example.com` and `/watchlist`.
8. As an admin, run `/stats` and `/backup`. Check host logs for “Database initialized” and “Starting WHOIS bot”.

## Environment configuration

Use the same token/admin/database settings you already have. Optional settings:

```env
FREE_TOKENS=3
RESET_HOURS=24
MAX_HISTORY=10
ANTI_SPAM_SECONDS=1
LOOKUP_TIMEOUT_SECONDS=15
WATCH_LIMIT_FREE=5
WATCH_LIMIT_PRO=25
MONITOR_INTERVAL_HOURS=24
BACKUP_DIR=backups
BACKUP_RETENTION_DAYS=7
```

The `.env.example` is a template only. Do not replace a working host's environment variables with the sample token.

## User commands

- `/start`, `/help`
- `/balance` or `/tokens`
- `/history`
- `/profile`, `/mystats`
- `/watch example.com`, `/unwatch example.com`, `/watchlist`
- `/buypro`
- Send a domain like `example.com` for a WHOIS/RDAP and DNS lookup.

Free users get 3 tokens per rolling 24 hours by default. A token is charged only after usable WHOIS/RDAP registration data is retrieved. Failed lookups remain free. Active PRO users have unlimited lookups. Default watchlist limits are 5 domains for Standard and 25 for PRO; these can be adjusted with environment variables.

## Admin commands

- `/admin`, `/stats`
- `/addpro USER_ID DAYS`, `/removepro USER_ID`
- `/addtokens USER_ID AMOUNT`, `/settokens USER_ID AMOUNT`
- `/checkuser USER_ID`, `/ban USER_ID`, `/unban USER_ID`
- `/broadcast MESSAGE`
- `/backup` — sends a consistent SQLite backup to the admin who ran the command.

Admin authorization uses Telegram numeric IDs from `ADMIN_IDS`, not usernames.

## Backup and monitoring notes

The bot makes an automatic local backup after startup and then every 24 hours, retaining recent `.db` backup files according to `BACKUP_RETENTION_DAYS`. `/backup` is the safer way to download a copy off-host. If FadeHost uses ephemeral storage, configure a persistent volume/path or download backups regularly; local backups on an ephemeral filesystem may disappear after redeploys.

Monitoring runs through the JobQueue included in `python-telegram-bot[job-queue]`. If the host sleeps/stops the process, checks and alerts pause until it runs again. The monitor processes up to 200 watched domains per run to reduce load. DNS/expiry checks are best-effort: registry data may be hidden, rate-limited, or unavailable. Verify expiry dates with the registrar.

## Important

- Keep `.env`, the database, logs, and backups private.
- Never share `BOT_TOKEN` or publish a database backup.
- Run only one bot process against the same SQLite database.
- Use the **same `DATABASE_PATH`** as your current deployment to preserve users, tokens, PRO status, and history.
