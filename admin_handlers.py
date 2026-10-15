import asyncio
import logging
from datetime import datetime, timezone
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import TelegramError, RetryAfter, TimedOut, NetworkError
from telegram.ext import ContextTypes, CommandHandler, CallbackQueryHandler
import database as db
from config import ADMIN_IDS

log = logging.getLogger(__name__)

def is_admin(update):
    return bool(update.effective_user and update.effective_user.id in ADMIN_IDS)

async def admin_only(update, context):
    if not is_admin(update):
        if update.effective_message:
            await update.effective_message.reply_text("⛔ Admin only.")
        return False
    return True

async def admin_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context): return
    keyboard = [
        [InlineKeyboardButton("📊 Stats", callback_data="adm:stats"),
         InlineKeyboardButton("👥 Users", callback_data="adm:users")],
        [InlineKeyboardButton("📢 Broadcast", callback_data="adm:broadcast"),
         InlineKeyboardButton("💎 Pro Management", callback_data="adm:pro")],
    ]
    await update.effective_message.reply_text("🛠 <b>Admin Dashboard</b>\nChoose an action below.",
        parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))

async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id not in ADMIN_IDS:
        await query.edit_message_text("⛔ Admin only.")
        return
    action = query.data.split(":", 1)[1]
    if action == "stats":
        s = await db.get_stats()
        text = (f"📊 <b>Statistics</b>\nUsers: {s['users']}\nActive/new today: {s['active_today']}"
                f"\nSuccessful lookups: {s['successful']}\nFailed lookups: {s['failed']}"
                f"\nFree users: {s['free']}\nPro users: {s['pro']}\nTokens used today: {s['tokens_used_today']}")
    elif action == "users":
        s = await db.get_stats()
        text = f"👥 Total users: {s['users']}\nUse /checkuser USER_ID to inspect a user."
    elif action == "broadcast":
        text = "📢 Send <code>/broadcast your message here</code> to broadcast to all unbanned users."
    else:
        text = "💎 Pro management:\n/addpro USER_ID DAYS\n/removepro USER_ID"
    await query.edit_message_text(text, parse_mode=ParseMode.HTML)

async def stats_command(update, context):
    if not await admin_only(update, context): return
    s = await db.get_stats()
    await update.effective_message.reply_text(
        f"📊 Stats\nTotal users: {s['users']}\nActive/new today: {s['active_today']}\n"
        f"Successful lookups: {s['successful']}\nFailed lookups: {s['failed']}\n"
        f"Free users: {s['free']}\nPro users: {s['pro']}\nTokens used today: {s['tokens_used_today']}")

async def addpro_command(update, context):
    if not await admin_only(update, context): return
    try:
        user_id, days = int(context.args[0]), int(context.args[1])
        if days < 1 or days > 36500: raise ValueError
        until = await db.add_pro(user_id, days)
        log.warning("ADMIN %s added %s days Pro to %s", update.effective_user.id, days, user_id)
        await update.effective_message.reply_text(f"✅ Pro enabled for {user_id} until {until.isoformat()}.")
    except (IndexError, ValueError):
        await update.effective_message.reply_text("Usage: /addpro USER_ID DAYS")

async def removepro_command(update, context):
    if not await admin_only(update, context): return
    try:
        user_id = int(context.args[0])
        await db.remove_pro(user_id)
        log.warning("ADMIN %s removed Pro from %s", update.effective_user.id, user_id)
        await update.effective_message.reply_text(f"✅ Pro removed for {user_id}.")
    except (IndexError, ValueError):
        await update.effective_message.reply_text("Usage: /removepro USER_ID")

async def token_command(update, context, exact=False):
    if not await admin_only(update, context): return
    try:
        user_id, amount = int(context.args[0]), int(context.args[1])
        if amount < 0: raise ValueError
        user = await db.adjust_tokens(user_id, amount, exact=exact)
        log.warning("ADMIN %s %s tokens for %s amount=%s", update.effective_user.id,
                    "set" if exact else "added", user_id, amount)
        await update.effective_message.reply_text(f"✅ User {user_id} now has {user['tokens']} tokens.")
    except (IndexError, ValueError):
        command = "/settokens" if exact else "/addtokens"
        await update.effective_message.reply_text(f"Usage: {command} USER_ID AMOUNT")

async def addtokens_command(update, context):
    await token_command(update, context, exact=False)

async def settokens_command(update, context):
    await token_command(update, context, exact=True)

async def userinfo_command(update, context):
    if not await admin_only(update, context): return
    try:
        user_id = int(context.args[0])
        u = await db.get_user_admin_info(user_id)
        if not u:
            await update.effective_message.reply_text("User not found.")
            return
        history = "\n".join(f"• {x['domain']} — {x['timestamp'][:10]}" for x in u["history"]) or "None"
        text = (f"👤 User: {user_id}\nUsername: @{u.get('username') or 'N/A'}\n"
                f"First name: {u.get('first_name') or 'N/A'}\nTokens: {u['tokens']}\n"
                f"Pro: {bool(u['is_pro'])}\nPro until: {u.get('pro_until') or 'N/A'}\n"
                f"Total lookups: {u['total_lookups']}\nFailed count: {u['failed_count']}\n"
                f"Banned: {bool(u['is_banned'])}\nLast successful:\n{history}")
        await update.effective_message.reply_text(text)
    except (IndexError, ValueError):
        await update.effective_message.reply_text("Usage: /checkuser USER_ID")

async def ban_command(update, context):
    if not await admin_only(update, context): return
    try:
        uid = int(context.args[0]); await db.set_banned(uid, True)
        log.warning("ADMIN %s banned %s", update.effective_user.id, uid)
        await update.effective_message.reply_text(f"🚫 User {uid} banned.")
    except (IndexError, ValueError):
        await update.effective_message.reply_text("Usage: /ban USER_ID")

async def unban_command(update, context):
    if not await admin_only(update, context): return
    try:
        uid = int(context.args[0]); await db.set_banned(uid, False)
        log.warning("ADMIN %s unbanned %s", update.effective_user.id, uid)
        await update.effective_message.reply_text(f"✅ User {uid} unbanned.")
    except (IndexError, ValueError):
        await update.effective_message.reply_text("Usage: /unban USER_ID")

async def broadcast_command(update, context):
    if not await admin_only(update, context): return
    message = " ".join(context.args).strip()
    if not message:
        await update.effective_message.reply_text("Usage: /broadcast MESSAGE")
        return
    ids = await db.get_all_user_ids()
    status = await update.effective_message.reply_text(f"📢 Broadcasting to {len(ids)} users…")
    sent = failed = 0
    for uid in ids:
        try:
            await context.bot.send_message(chat_id=uid, text=message)
            sent += 1
        except RetryAfter as exc:
            await asyncio.sleep(float(getattr(exc, "retry_after", 1)) + 0.5)
            try:
                await context.bot.send_message(chat_id=uid, text=message); sent += 1
            except TelegramError:
                failed += 1
        except (TelegramError, Exception):
            failed += 1
        await asyncio.sleep(0.05)
    log.warning("ADMIN %s broadcast complete sent=%s failed=%s", update.effective_user.id, sent, failed)
    await status.edit_text(f"📢 Broadcast complete.\nSent: {sent}\nFailed: {failed}")

def register_admin_handlers(app):
    app.add_handler(CommandHandler("admin", admin_start))
    app.add_handler(CallbackQueryHandler(admin_callback, pattern=r"^adm:"))
    app.add_handler(CommandHandler("stats", stats_command))
    app.add_handler(CommandHandler("addpro", addpro_command))
    app.add_handler(CommandHandler("removepro", removepro_command))
    app.add_handler(CommandHandler("addtokens", addtokens_command))
    app.add_handler(CommandHandler("settokens", settokens_command))
    app.add_handler(CommandHandler("checkuser", userinfo_command))
    app.add_handler(CommandHandler("ban", ban_command))
    app.add_handler(CommandHandler("unban", unban_command))
    app.add_handler(CommandHandler("broadcast", broadcast_command))
