import asyncio
import html
import io
import logging
import json
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

import database as db
from config import (BOT_TOKEN, ADMIN_IDS, FREE_TOKENS, RESET_HOURS, MAX_HISTORY, ANTI_SPAM_SECONDS,
                     WATCH_LIMIT_FREE, WATCH_LIMIT_PRO, MONITOR_INTERVAL_HOURS, BACKUP_DIR, BACKUP_RETENTION_DAYS)
from whois_lookup import get_whois_data, get_dns_data
from admin_handlers import register_admin_handlers

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[logging.FileHandler("bot.log", encoding="utf-8"), logging.StreamHandler()],
)
log = logging.getLogger(__name__)
last_message_time = {}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$")

def normalize_domain(raw):
    value = raw.strip().lower()
    if "://" in value:
        parsed = urlparse(value)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None
        value = parsed.hostname or ""
    if value.startswith("www."):
        value = value[4:]
    value = value.rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253 or not DOMAIN_RE.fullmatch(value):
        return None
    labels = value.split(".")
    if any(len(label) > 63 for label in labels):
        return None
    return value

def fmt(value):
    if not value:
        return "N/A"
    if isinstance(value, list):
        return ", ".join(str(x) for x in value[:10]) or "N/A"
    return str(value)

def remaining_text(seconds):
    hours, rem = divmod(max(0, seconds), 3600)
    minutes = rem // 60
    return f"{hours}h {minutes}m"

def format_result(domain, whois_data, dns_data, requested_by=None, is_pro=False):
    fields = [
        ("🏢 Registrar", whois_data.get("registrar")),
        ("📅 Created", whois_data.get("creation_date")),
        ("⏳ Expires", whois_data.get("expiration_date")),
        ("📡 Name Servers", whois_data.get("name_servers")),
        ("📧 Emails", whois_data.get("emails")),
        ("📊 Status", whois_data.get("status")),
        ("🧾 Source", whois_data.get("source")),
    ]
    lines = [f"🌐 <b>Domain:</b> <code>{html.escape(domain)}</code>"]
    for label, value in fields:
        lines.append(f"{label}: {html.escape(fmt(value))}")
    lines.append("\n📡 <b>DNS Records</b>")
    for kind in ("NS", "A", "AAAA", "CNAME", "MX", "TXT"):
        vals = dns_data.get(kind) or []
        display = ", ".join(str(x) for x in vals[:8]) if vals else "N/A"
        if len(display) > 700:
            display = display[:697] + "..."
        lines.append(f"<b>{kind}:</b> {html.escape(display)}")
    if requested_by:
        lines.append(f"\n👤 <b>Requested by:</b> {html.escape(requested_by)}")
    if is_pro:
        lines.append("💎 <b>PRO MEMBER</b>")
    lines.append("\n<i>Powered by Jazib Ali Abbas</i>")
    return "\n".join(lines)

def _pdf_value(value):
    if value is None or value == "" or value == []:
        return "Not available"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in list(value)[:20]) or "Not available"
    return str(value)

def build_pdf_report(domain, whois_data, dns_data, telegram_user, is_pro=False):
    """Build a branded, modern PDF report in memory."""
    buffer = io.BytesIO()
    navy = colors.HexColor("#101B35")
    teal = colors.HexColor("#00A6A6")
    pale = colors.HexColor("#F2F6FA")
    muted = colors.HexColor("#637083")
    border = colors.HexColor("#DCE4ED")

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=22 * mm, bottomMargin=20 * mm,
        title=f"WHOIS Report - {domain}",
        author="Jazib Ali Abbas",
        subject=f"WHOIS and DNS report for {domain}",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=23, leading=28, textColor=colors.white, alignment=TA_LEFT,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="ReportSub", parent=styles["Normal"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=colors.HexColor("#D6E4F0"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHead", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=11, leading=14, textColor=navy, spaceBefore=10, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="Cell", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=8.5, leading=11, textColor=navy, wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="CellLabel", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=8.5, leading=11, textColor=muted,
    ))
    styles.add(ParagraphStyle(
        name="SmallMuted", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=8, leading=11, textColor=muted,
    ))

    def para(value, style="Cell"):
        safe = html.escape(str(value)).replace("\n", "<br/>")
        return Paragraph(safe, styles[style])

    username = f"@{telegram_user.username}" if getattr(telegram_user, "username", None) else f"Telegram ID {getattr(telegram_user, 'id', 'N/A')}"
    tier = "PRO MEMBER" if is_pro else "STANDARD MEMBER"
    generated = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    hero = Table([
        [Paragraph("DOMAIN INTELLIGENCE", ParagraphStyle(
            "Eyebrow", parent=styles["Normal"], fontName="Helvetica-Bold",
            fontSize=8, textColor=colors.HexColor("#69E0D5"), leading=11,
        ))],
        [Paragraph(html.escape(domain), styles["ReportTitle"])],
        [Paragraph(f"WHOIS &amp; DNS REPORT  •  {html.escape(tier)}", styles["ReportSub"])],
    ], colWidths=[174 * mm])
    hero.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), navy),
        ("BOX", (0, 0), (-1, -1), 0, navy),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, 0), 13),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 13),
    ]))

    story = [hero, Spacer(1, 9 * mm)]
    meta = Table([
        [para("REQUESTED BY", "CellLabel"), para(username), para("GENERATED", "CellLabel"), para(generated)],
    ], colWidths=[27 * mm, 48 * mm, 24 * mm, 75 * mm])
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pale),
        ("BOX", (0, 0), (-1, -1), 0.5, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([meta, Paragraph("REGISTRATION DETAILS", styles["SectionHead"])])

    details = [
        ("Domain", domain),
        ("Registrar", _pdf_value(whois_data.get("registrar"))),
        ("Created", _pdf_value(whois_data.get("creation_date"))),
        ("Expiration", _pdf_value(whois_data.get("expiration_date"))),
        ("Last Updated", _pdf_value(whois_data.get("updated_date"))),
        ("Name Servers", _pdf_value(whois_data.get("name_servers"))),
        ("Domain Status", _pdf_value(whois_data.get("status"))),
        ("Registrant Emails", _pdf_value(whois_data.get("emails"))),
        ("Organization", _pdf_value(whois_data.get("org"))),
        ("Country", _pdf_value(whois_data.get("country"))),
        ("Data Source", _pdf_value(whois_data.get("source"))),
    ]
    rows = [[para("FIELD", "CellLabel"), para("VALUE", "CellLabel")]]
    rows += [[para(label, "CellLabel"), para(value)] for label, value in details]
    table = Table(rows, colWidths=[43 * mm, 131 * mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), pale),
        ("TEXTCOLOR", (0, 0), (-1, 0), navy),
        ("LINEBELOW", (0, 0), (-1, 0), 1, teal),
        ("GRID", (0, 1), (-1, -1), 0.35, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFCFE")]),
    ]))
    story.extend([table, Paragraph("DNS RECORDS", styles["SectionHead"])])

    dns_rows = [[para("TYPE", "CellLabel"), para("RECORD VALUES", "CellLabel")]]
    for kind in ("NS", "A", "AAAA", "CNAME", "MX", "TXT"):
        values = (dns_data or {}).get(kind) or []
        dns_rows.append([para(kind, "CellLabel"), para(_pdf_value(values))])
    dns_table = Table(dns_rows, colWidths=[25 * mm, 149 * mm], repeatRows=1, hAlign="LEFT")
    dns_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), pale),
        ("LINEBELOW", (0, 0), (-1, 0), 1, teal),
        ("GRID", (0, 1), (-1, -1), 0.35, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFCFE")]),
    ]))
    story.extend([
        dns_table,
        Spacer(1, 8 * mm),
        Paragraph("This report contains publicly available WHOIS/RDAP and DNS information at the time of generation. Some registration fields may be hidden by privacy services or unavailable from the registry.", styles["SmallMuted"]),
    ])

    def decorate(canvas, document):
        canvas.saveState()
        page_width, page_height = A4
        canvas.setFillColor(teal)
        canvas.rect(0, page_height - 4 * mm, page_width, 4 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(border)
        canvas.line(18 * mm, 14 * mm, page_width - 18 * mm, 14 * mm)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(navy)
        canvas.drawString(18 * mm, 9 * mm, "Powered by Jazib Ali Abbas")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(muted)
        canvas.drawRightString(page_width - 18 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    buffer.seek(0)
    return buffer

def user_keyboard(domain):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔁 Re-check", callback_data=f"recheck:{domain}"),
         InlineKeyboardButton("📑 Export branded PDF", callback_data=f"export:{domain}")],
        [InlineKeyboardButton("🔍 Check Another", callback_data="another")],
    ])

async def ensure_user(update):
    u = update.effective_user
    return await db.create_user(u.id, u.username, u.first_name)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await ensure_user(update)
    await update.effective_message.reply_text(
        "Welcome to WHOIS Bot 🌐\nYou have 3 free tokens per 24h. 1 domain = 1 token. "
        "Failed lookups are free. /help to see commands.\n\nPowered by Jazib Ali Abbas"
    )

async def help_command(update, context):
    await ensure_user(update)
    await update.effective_message.reply_text(
        "🌐 <b>WHOIS Bot Help</b>\nSend a domain such as <code>google.com</code> to look it up.\n\n"
        "/start — Start the bot\n/balance or /tokens — Token balance\n/history — Recent successful lookups\n"
        "/buypro — Pro information\n/profile — Account profile\n/mystats — Your usage statistics\n"
        "/watch domain.com — Monitor a domain\n/unwatch domain.com — Stop monitoring\n/watchlist — List monitored domains\n/help — This message\n\n"
        "Each successful WHOIS lookup costs 1 token. Failed lookups are free. "
        "Free tokens reset every 24 hours on a rolling basis.\n\n<i>Powered by Jazib Ali Abbas</i>",
        parse_mode=ParseMode.HTML
    )

async def balance_command(update, context):
    await ensure_user(update)
    access = await db.can_search_and_get_tokens(update.effective_user.id)
    user = access.get("user") or {}
    if access.get("pro"):
        text = f"Tokens: Unlimited\nResets in: {remaining_text(_reset_seconds(user))}\nPro: Yes"
    else:
        text = f"Tokens: {user.get('tokens', 0)}/{FREE_TOKENS}, Resets in: {remaining_text(_reset_seconds(user))}, Pro: No"
    await update.effective_message.reply_text(f"{text}\n\nPowered by Jazib Ali Abbas")

async def profile_command(update, context):
    await ensure_user(update)
    user = await db.reset_tokens_if_needed(update.effective_user.id)
    access = await db.can_search_and_get_tokens(update.effective_user.id)
    stats = await db.get_personal_stats(update.effective_user.id)
    pro_until = user.get("pro_until") if access.get("pro") else None
    username = f"@{update.effective_user.username}" if update.effective_user.username else "No public username"
    tier = "💎 PRO" if access.get("pro") else "Standard"
    lines = ["👤 <b>Your Profile</b>", f"Name: {html.escape(update.effective_user.full_name)}",
             f"Username: {html.escape(username)}", f"Telegram ID: <code>{update.effective_user.id}</code>",
             f"Plan: {tier}", f"Tokens: {'Unlimited' if access.get('pro') else str(user.get('tokens', 0)) + '/' + str(FREE_TOKENS)}",
             f"Total successful lookups: {stats['successful']}", f"Lookups in last 7 days: {stats['last7']}",
             f"Failed attempts: {stats['failed']}", f"Watched domains: {stats['watched']}"]
    if pro_until:
        lines.append(f"PRO expires: {html.escape(pro_until[:16].replace('T', ' '))} UTC")
    lines.append("\n<i>Powered by Jazib Ali Abbas</i>")
    await update.effective_message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)

async def mystats_command(update, context):
    await ensure_user(update)
    stats = await db.get_personal_stats(update.effective_user.id)
    await update.effective_message.reply_text(
        "📈 <b>Your Usage Statistics</b>\n"
        f"Successful lookups: {stats['successful']}\nFailed attempts: {stats['failed']}\n"
        f"Successful lookups in last 7 days: {stats['last7']}\nWatched domains: {stats['watched']}\n\n"
        "Use /profile for your account details.\n<i>Powered by Jazib Ali Abbas</i>", parse_mode=ParseMode.HTML)

async def watch_command(update, context):
    await ensure_user(update)
    if not context.args:
        await update.effective_message.reply_text("Usage: /watch example.com\nI’ll check for DNS changes and domain expiry alerts.")
        return
    domain = normalize_domain(context.args[0])
    if not domain or len(context.args) > 1:
        await update.effective_message.reply_text("❌ Send one valid domain, e.g. /watch example.com")
        return
    access = await db.can_search_and_get_tokens(update.effective_user.id)
    if not access.get("allowed") and access.get("reason") != "no_tokens":
        await update.effective_message.reply_text(f"❌ {access.get('reason', 'Not allowed.')}")
        return
    is_pro = bool(access.get("pro"))
    limit = WATCH_LIMIT_PRO if is_pro else WATCH_LIMIT_FREE
    result = await db.add_watch(update.effective_user.id, domain, limit)
    if result["exists"]:
        await update.effective_message.reply_text(f"👀 <code>{html.escape(domain)}</code> is already on your watchlist.", parse_mode=ParseMode.HTML)
    elif not result["ok"]:
        await update.effective_message.reply_text(f"Your plan supports {limit} watched domains. Remove one with /unwatch domain.com or upgrade via /buypro.")
    else:
        await update.effective_message.reply_text(
            f"🔔 Added <code>{html.escape(domain)}</code> to your watchlist ({result['count']}/{limit}).\n"
            "I’ll check daily for DNS changes and expiry milestones (30, 7 and 1 day when expiry data is available).\n\n"
            "Monitoring is best-effort and depends on registry/DNS availability.\n<i>Powered by Jazib Ali Abbas</i>", parse_mode=ParseMode.HTML)

async def unwatch_command(update, context):
    await ensure_user(update)
    if not context.args:
        await update.effective_message.reply_text("Usage: /unwatch example.com")
        return
    domain = normalize_domain(context.args[0])
    if not domain:
        await update.effective_message.reply_text("❌ Invalid domain.")
        return
    removed = await db.remove_watch(update.effective_user.id, domain)
    await update.effective_message.reply_text("✅ Removed from watchlist." if removed else "That domain isn’t on your watchlist.")

async def watchlist_command(update, context):
    await ensure_user(update)
    watches = await db.get_watches(update.effective_user.id)
    if not watches:
        await update.effective_message.reply_text("Your watchlist is empty. Add a domain with /watch example.com")
        return
    lines = ["👀 <b>Your Domain Watchlist</b>"]
    for item in watches:
        checked = (item.get("last_checked") or "Not checked yet")[:16].replace("T", " ")
        lines.append(f"• <code>{html.escape(item['domain'])}</code> — checked: {html.escape(checked)} UTC")
    lines.append("\nRemove a domain with /unwatch example.com\n<i>Powered by Jazib Ali Abbas</i>")
    await update.effective_message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)

def _expiration_date(value):
    if isinstance(value, (list, tuple)):
        value = next((item for item in value if item), None)
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(text[:19], fmt).date()
            except ValueError:
                continue
    return None

async def monitor_watches_job(context):
    watches = await db.get_all_watches(limit=200)
    for watch in watches:
        try:
            whois_data, dns_data = await asyncio.gather(
                get_whois_data(watch["domain"]), get_dns_data(watch["domain"]), return_exceptions=True)
            if isinstance(whois_data, Exception) or not whois_data:
                log.info("Monitor skipped %s: no WHOIS data", watch["domain"])
                continue
            if isinstance(dns_data, Exception) or not isinstance(dns_data, dict):
                dns_data = {}
            snapshot = {kind: sorted(str(x) for x in (dns_data.get(kind) or [])) for kind in ("NS", "A", "AAAA", "CNAME", "MX", "TXT")}
            previous = None
            if watch.get("last_snapshot"):
                try:
                    previous = json.loads(watch["last_snapshot"])
                except (ValueError, TypeError):
                    previous = None
            try:
                await context.bot.send_chat_action(chat_id=watch["user_id"], action="typing")
            except TelegramError:
                pass
            if previous is not None and previous != snapshot:
                changed = [key for key in snapshot if previous.get(key, []) != snapshot.get(key, [])]
                if changed:
                    await context.bot.send_message(
                        chat_id=watch["user_id"],
                        text=f"🔔 <b>DNS change detected</b>\nDomain: <code>{html.escape(watch['domain'])}</code>\nChanged record types: {', '.join(changed)}\n\n<i>Powered by Jazib Ali Abbas</i>",
                        parse_mode=ParseMode.HTML)
            expiry = _expiration_date(whois_data.get("expiration_date"))
            stage = int(watch.get("expiry_stage") or 0)
            if expiry:
                days_left = (expiry - datetime.now(timezone.utc).date()).days
                new_stage = 3 if days_left <= 1 else 2 if days_left <= 7 else 1 if days_left <= 30 else 0
                if new_stage > stage and new_stage > 0:
                    label = "1 day or less" if new_stage == 3 else "7 days or less" if new_stage == 2 else "30 days or less"
                    await context.bot.send_message(
                        chat_id=watch["user_id"],
                        text=f"⏳ <b>Domain expiry alert</b>\n<code>{html.escape(watch['domain'])}</code> may expire in <b>{label}</b>.\nReported expiration date: {expiry.isoformat()}\nPlease verify with your registrar.\n\n<i>Powered by Jazib Ali Abbas</i>",
                        parse_mode=ParseMode.HTML)
                    stage = new_stage
                elif days_left > 30:
                    stage = 0
            await db.update_watch_snapshot(watch["id"], snapshot, stage)
            await asyncio.sleep(0.25)
        except TelegramError as exc:
            log.info("Could not notify watcher %s for %s: %s", watch.get("user_id"), watch.get("domain"), exc)
        except Exception:
            log.exception("Watch monitor error for %s", watch.get("domain"))

async def automatic_backup_job(context):
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_UTC")
        path = os.path.join(BACKUP_DIR, f"whois_bot_{stamp}.db")
        await db.create_backup(path)
        cutoff = datetime.now(timezone.utc).timestamp() - max(1, BACKUP_RETENTION_DAYS) * 86400
        for name in os.listdir(BACKUP_DIR):
            candidate = os.path.join(BACKUP_DIR, name)
            if name.endswith(".db") and os.path.isfile(candidate) and os.path.getmtime(candidate) < cutoff:
                try: os.remove(candidate)
                except OSError: log.warning("Could not prune backup %s", candidate)
        log.info("Automatic database backup created: %s", path)
    except Exception:
        log.exception("Automatic database backup failed")

def _reset_seconds(user):
    from database import parse_dt, now_utc
    last = parse_dt(user.get("last_reset"))
    if not last: return 0
    return max(0, int((last + timedelta(hours=RESET_HOURS) - now_utc()).total_seconds()))

async def history_command(update, context):
    await ensure_user(update)
    history = await db.get_history(update.effective_user.id, MAX_HISTORY)
    if not history:
        await update.effective_message.reply_text("No successful lookups yet.")
        return
    lines = ["📜 <b>Your recent successful lookups</b>"]
    for item in history:
        lines.append(f"• <code>{html.escape(item['domain'])}</code> — {html.escape(item['timestamp'][:16].replace('T', ' '))}")
    lines.append("\n<i>Powered by Jazib Ali Abbas</i>")
    await update.effective_message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)

async def buypro_command(update, context):
    await ensure_user(update)
    await update.effective_message.reply_text(
        "💎 <b>WHOIS Bot Pro</b>\nPro gives unlimited lookups while your subscription is active.\n"
        "Contact the bot administrator to arrange access.\n\n<i>Powered by Jazib Ali Abbas</i>",
        parse_mode=ParseMode.HTML
    )

async def perform_lookup(update, context, domain, callback_query=None):
    user_id = update.effective_user.id
    access = await db.can_search_and_get_tokens(user_id)
    if not access.get("allowed"):
        if access.get("reason") == "no_tokens":
            text = (f"❌ You used {FREE_TOKENS}/{FREE_TOKENS} tokens today. "
                    f"Refill in {remaining_text(access.get('seconds_left', 0))}. "
                    "Get Pro with /buypro for unlimited.")
        else:
            text = f"❌ {access.get('reason', 'Lookup not allowed.')}"
        if callback_query:
            await callback_query.message.reply_text(text)
        else:
            await update.effective_message.reply_text(text)
        return
    status_msg = None
    try:
        if callback_query:
            status_msg = await callback_query.message.reply_text(f"🔎 Looking up <code>{html.escape(domain)}</code>…", parse_mode=ParseMode.HTML)
        else:
            status_msg = await update.effective_message.reply_text(f"🔎 Looking up <code>{html.escape(domain)}</code>…", parse_mode=ParseMode.HTML)
        whois_task = asyncio.create_task(get_whois_data(domain))
        dns_task = asyncio.create_task(get_dns_data(domain))
        whois_data, dns_data = await asyncio.gather(whois_task, dns_task, return_exceptions=True)
        if isinstance(whois_data, Exception) or not whois_data:
            reason = "No registration data found or WHOIS/RDAP services timed out."
            await db.log_failed(user_id, domain, reason)
            current = await db.get_user(user_id)
            await status_msg.edit_text(
                f"❌ Failed for <code>{html.escape(domain)}</code>. Reason: {html.escape(reason)}\n"
                f"Your tokens are NOT charged. You still have {current['tokens']}/{FREE_TOKENS}.",
                parse_mode=ParseMode.HTML
            )
            return
        if isinstance(dns_data, Exception) or not isinstance(dns_data, dict):
            dns_data = {k: [] for k in ("NS", "A", "AAAA", "CNAME", "MX", "TXT")}
        # Re-check and charge atomically only after valid WHOIS/RDAP data exists.
        latest = await db.can_search_and_get_tokens(user_id)
        if not latest.get("allowed"):
            await status_msg.edit_text("❌ Your tokens changed while this lookup was running. No token was charged.")
            return
        user = await db.use_token(user_id, success=True, domain=domain)
        user_label = f"@{update.effective_user.username}" if update.effective_user.username else f"ID {user_id}"
        result_text = format_result(domain, whois_data, dns_data, user_label, bool(user and user.get("is_pro")))
        if user and not user.get("is_pro"):
            result_text += f"\n\n🎟️ Tokens remaining: {user['tokens']}/{FREE_TOKENS}"
        await status_msg.edit_text(result_text, parse_mode=ParseMode.HTML, reply_markup=user_keyboard(domain))
    except Exception as exc:
        log.exception("Lookup handler error for %s user %s", domain, user_id)
        await db.log_failed(user_id, domain, f"Unhandled error: {type(exc).__name__}: {exc}")
        try:
            current = await db.get_user(user_id)
            await status_msg.edit_text(
                f"❌ Failed for <code>{html.escape(domain)}</code>. Reason: temporary lookup error.\n"
                f"Your tokens are NOT charged. You still have {current.get('tokens', 0)}/{FREE_TOKENS}.",
                parse_mode=ParseMode.HTML
            )
        except Exception:
            pass

async def domain_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.effective_user or not update.effective_message:
        return
    await ensure_user(update)
    uid = update.effective_user.id
    user = await db.get_user(uid)
    if user and user.get("is_banned"):
        await update.effective_message.reply_text("⛔ Your account is banned.")
        return
    now = time.monotonic()
    if now - last_message_time.get(uid, 0) < ANTI_SPAM_SECONDS:
        return
    last_message_time[uid] = now
    raw = update.effective_message.text or ""
    domain = normalize_domain(raw)
    if not domain:
        if "." in raw and len(raw) < 300:
            await db.log_failed(uid, raw[:253], "Invalid domain format")
            await update.effective_message.reply_text("❌ Invalid domain. Send a domain like example.com (without paths or extra text).")
        return
    await perform_lookup(update, context, domain)

async def result_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == "another":
        await query.message.reply_text("🔍 Send the next domain, e.g. example.com")
        return
    action, domain = query.data.split(":", 1)
    if action == "recheck":
        normalized = normalize_domain(domain)
        if normalized:
            await perform_lookup(update, context, normalized, callback_query=query)
    elif action == "export":
        # Export from a fresh lookup without charging again: use existing last successful record only for data availability.
        whois_data = await get_whois_data(domain)
        dns_data = await get_dns_data(domain)
        if not whois_data:
            await query.message.reply_text("❌ Could not retrieve current data to export. No token charged.")
            return
        if not isinstance(dns_data, dict):
            dns_data = {k: [] for k in ("NS", "A", "AAAA", "CNAME", "MX", "TXT")}
        access = await db.can_search_and_get_tokens(update.effective_user.id)
        is_pro = bool(access.get("pro"))
        pdf = build_pdf_report(domain, whois_data, dns_data, update.effective_user, is_pro)
        pdf.name = f"{domain.replace('.', '_')}_whois_report.pdf"
        tier = "💎 PRO member" if is_pro else "Standard member"
        username = f"@{update.effective_user.username}" if update.effective_user.username else f"ID {update.effective_user.id}"
        await query.message.reply_document(
            document=InputFile(pdf, filename=pdf.name),
            caption=f"📑 Branded WHOIS report\n🌐 {domain}\n👤 {username} • {tier}\nPowered by Jazib Ali Abbas",
        )

async def error_handler(update, context):
    log.error("Unhandled Telegram update error: %s", context.error, exc_info=context.error)
    if isinstance(context.error, TelegramError):
        return

def main():
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is missing. Set it in your .env file.")
    app = Application.builder().token(BOT_TOKEN).build()

    async def post_init(application):
        await db.init_db()
        log.info("Database initialized")
        if application.job_queue:
            interval = max(1, MONITOR_INTERVAL_HOURS) * 3600
            application.job_queue.run_repeating(monitor_watches_job, interval=interval, first=30, name="domain_watch_monitor")
            application.job_queue.run_repeating(automatic_backup_job, interval=24 * 3600, first=60, name="database_backup")
        else:
            log.warning("Job queue unavailable; domain monitoring and automatic backups are disabled")

    app.post_init = post_init
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("balance", balance_command))
    app.add_handler(CommandHandler("tokens", balance_command))
    app.add_handler(CommandHandler("history", history_command))
    app.add_handler(CommandHandler("profile", profile_command))
    app.add_handler(CommandHandler("mystats", mystats_command))
    app.add_handler(CommandHandler("watch", watch_command))
    app.add_handler(CommandHandler("unwatch", unwatch_command))
    app.add_handler(CommandHandler("watchlist", watchlist_command))
    app.add_handler(CommandHandler("buypro", buypro_command))
    app.add_handler(CallbackQueryHandler(result_callback, pattern=r"^(recheck:|export:|another$)"))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, domain_message))
    register_admin_handlers(app)
    app.add_error_handler(error_handler)
    log.info("Starting WHOIS bot")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
