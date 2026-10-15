# Domain WHOIS + NS Lookup Telegram Bot

Async Telegram bot using Python 3.11+, `python-telegram-bot`, SQLite/aiosqlite, python-whois, dnspython, RDAP, and Google DNS-over-HTTPS.

## Setup

1. Install Python 3.11 or newer.
2. Create a bot with Telegram's `@BotFather` and copy its token.
3. Copy `.env.example` to `.env`.
4. Put your token in `BOT_TOKEN` and your Telegram numeric user ID(s) in `ADMIN_IDS`, separated by commas.
5. Install dependencies and run:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Keep `.env`, `bot.db`, and `bot.log` private. Never publish your bot token. Run one bot process against this SQLite database at a time.

## User commands

- `/start` — welcome
- `/help` — commands and usage
- `/balance` or `/tokens` — balance and reset time
- `/history` — last successful lookups
- `/buypro` — Pro information

Send a domain such as `example.com`. Successful WHOIS/RDAP lookups cost one token for free users; failed lookups do not cost tokens. DNS results are included when available. Free tokens reset after the configured rolling interval from `last_reset`. Pro is unlimited while active.

## Admin commands

- `/admin` — inline admin dashboard
- `/stats` — aggregate statistics
- `/addpro USER_ID DAYS`
- `/removepro USER_ID`
- `/addtokens USER_ID AMOUNT`
- `/settokens USER_ID AMOUNT`
- `/checkuser USER_ID`
- `/ban USER_ID`
- `/unban USER_ID`
- `/broadcast MESSAGE`

Admin IDs are configured in `.env`. Admin commands are checked against Telegram numeric IDs, not usernames. Admin actions are logged to `bot.log`.

## Configuration

Edit `.env`:
- `FREE_TOKENS=3`
- `RESET_HOURS=24`
- `MAX_HISTORY=10`
- `ANTI_SPAM_SECONDS=1`
- `LOOKUP_TIMEOUT_SECONDS=15`
- `DATABASE_PATH=bot.db`

## Token accounting notes

The bot charges only after it receives usable registration data from WHOIS or RDAP. DNS results alone do not constitute a successful WHOIS lookup. Failed lookup attempts are recorded in `failed_log`. Successful lookups are recorded in `usage_log` and increment `total_lookups`.

## Operational notes

WHOIS servers and RDAP registries can rate-limit or omit fields. Domain registration privacy can hide contact information. DNS records can legitimately be absent. Results are best-effort and are not a substitute for registrar records. Use a process manager (systemd, Docker, or a hosting platform's worker service) to keep the bot running.
