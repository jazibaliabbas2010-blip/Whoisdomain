import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(item.strip()) for item in os.getenv("ADMIN_IDS", "").split(",")
    if item.strip().isdigit()
}
FREE_TOKENS = int(os.getenv("FREE_TOKENS", "3"))
RESET_HOURS = int(os.getenv("RESET_HOURS", "24"))
MAX_HISTORY = int(os.getenv("MAX_HISTORY", "10"))
ANTI_SPAM_SECONDS = float(os.getenv("ANTI_SPAM_SECONDS", "1"))
DATABASE_PATH = os.getenv("DATABASE_PATH", "bot.db")
PRO_DAILY_TOKENS = int(os.getenv("PRO_DAILY_TOKENS", "1000"))
LOOKUP_TIMEOUT_SECONDS = int(os.getenv("LOOKUP_TIMEOUT_SECONDS", "15"))
