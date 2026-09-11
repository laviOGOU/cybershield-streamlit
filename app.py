import asyncio
import hashlib
import logging
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests
import streamlit as st
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ==========================================
# 1. CONFIGURATION & LOGGING
# ==========================================
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("CyberShieldBot")

# Récupération du token via Streamlit Secrets ou Variable d'environnement
TELEGRAM_BOT_TOKEN = st.secrets.get(
    "TELEGRAM_BOT_TOKEN", os.getenv("TELEGRAM_BOT_TOKEN", "")
)
DB_PATH = "cybershield_bot.db"

# ==========================================
# 2. BASE DE DONNÉES & TÉLÉMÉTRIE (SQLITE)
# ==========================================


def init_db() -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    event_type TEXT NOT NULL,
                    detail TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    metric_key TEXT PRIMARY KEY,
                    metric_value INTEGER DEFAULT 0
                )
            """)
            keys = [
                "utilisateurs_uniques",
                "tests_mdp",
                "mdp_forts",
                "mdp_moyens",
                "mdp_faibles",
                "mdp_compromis",
                "tests_email",
                "emails_compromis",
            ]
            for key in keys:
                cursor.execute(
                    "INSERT OR IGNORE INTO metrics (metric_key, metric_value) VALUES (?, 0)",
                    (key,),
                )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Erreur DB init : {str(e)}")


def increment_metric(key: str, amount: int = 1) -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE metrics SET metric_value = metric_value + ? WHERE metric_key = ?",
                (amount, key),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Erreur update métrique {key} : {str(e)}")


def get_all_metrics() -> Dict[str, int]:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT metric_key, metric_value FROM metrics")
            return dict(cursor.fetchall())
    except sqlite3.Error as e:
        logger.error(f"Erreur lecture métriques : {str(e)}")
        return {}


def log_event(user_id: int, event_type: str, detail: str = "") -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO telemetry (user_id, event_type, detail) VALUES (?, ?, ?)",
                (user_id, event_type, detail),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Erreur log event : {str(e)}")


init_db()

# ==========================================
# 3. SERVICES D'AUDIT
# ==========================================


@dataclass
class PasswordCriterion:
    description: str
    is_met: bool
    recommendation: str


class PasswordSecurityEvaluator:

    @staticmethod
    def evaluate(password: str) -> Tuple[str, float, List[PasswordCriterion]]:
        criteria = [
            PasswordCriterion(
                "Au moins 12 caractères",
                len(password) >= 12,
                "Rallongez le mot de passe (12 à 16 caractères).",
            ),
            PasswordCriterion(
                "Lettres majuscules (A-Z)",
                bool(re.search(r"[A-Z]", password)),
                "Ajoutez au moins une majuscule.",
            ),
            PasswordCriterion(
                "Lettres minuscules (a-z)",
                bool(re.search(r"[a-z]", password)),
                "Ajoutez des minuscules.",
            ),
            PasswordCriterion(
                "Chiffres (0-9)",
                bool(re.search(r"[0-9]", password)),
                "Incorporez des chiffres.",
            ),
            PasswordCriterion(
                "Symboles spéciaux (!@#$%...)",
                bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
                "Ajoutez des caractères spéciaux.",
            ),
        ]

        score = sum(1 for c in criteria if c.is_met)
        percentage = (score / len(criteria)) * 100

        if score >= 5:
            level = "Fort"
        elif score >= 3:
            level = "Moyen"
        else:
            level = "Faible"

        return level, percentage, criteria

    @staticmethod
    def check_hibp_pwned(password: str) -> Optional[int]:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(
                url,
                headers={"User-Agent": "CyberShield-Telegram-Bot"},
                timeout=5,
            )
            if response.status_code == 200:
                for line in response.text.splitlines():
                    h, count = line.split(":")
                    if h == suffix:
                        return int(count)
                return 0
            return None
        except requests.RequestException:
            return None


class EmailBreachEvaluator:

    @staticmethod
    def check_breaches(email: str) -> Tuple[Optional[bool], List[str]]:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        try:
            response = requests.get(
                url,
                headers={"User-Agent": "CyberShield-Telegram-Bot"},
                timeout=5,
            )
            if response.status_code == 200:
                data = response.json()
                if "breaches" in data and data["breaches"]:
                    return True, data["breaches"][0]
                return False, []
            elif response.status_code == 404:
                return False, []
            return None, []
        except requests.RequestException:
            return None, []


# ==========================================
# 4. BOT TELEGRAM HANDLERS
# ==========================================


def get_main_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [
            InlineKeyboardButton(
                "🔑 Vérifier un Mot de Passe", callback_data="btn_pwd"
            )
        ],
        [
            InlineKeyboardButton(
                "📧 Vérifier un E-mail", callback_data="btn_email"
            )
        ],
        [
            InlineKeyboardButton(
                "📢 Actualités Piratages", callback_data="btn_news"
            ),
            InlineKeyboardButton(
                "📊 Télémétrie Bot", callback_data="btn_stats"
            ),
        ],
    ]
    return InlineKeyboardMarkup(keyboard)


async def start_command(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    user_id = update.effective_user.id
    log_event(user_id, "START_COMMAND")

    welcome_text = (
        "🛡️ *Bienvenue sur CyberShield Security Bot* 🛡️\n\n"
        "Votre assistant personnel d'évaluation de la sécurité numérique.\n\n"
        "👉 *Faites votre choix ci-dessous :*\n"
        "• Vérifiez la solidité d'un mot de passe.\n"
        "• Contrôlez la présence d'un e-mail dans des bases piratées.\n"
        "• Consultez les actualités de la cybersécurité."
    )
    await update.message.reply_text(
        welcome_text,
        parse_mode="Markdown",
        reply_markup=get_main_keyboard(),
    )


async def button_click_handler(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    query = update.callback_query
    await query.answer()

    if query.data == "btn_pwd":
        context.user_data["state"] = "AWAITING_PWD"
        await query.edit_message_text(
            "🔑 *Mode Audit Mot de Passe*\n\n"
            "Envoyez-moi le mot de passe que vous souhaitez tester dans le chat.\n\n"
            "🔒 *Confidentialité :* Analyse sécurisée et anonymisée.",
            parse_mode="Markdown",
        )
    elif query.data == "btn_email":
        context.user_data["state"] = "AWAITING_EMAIL"
        await query.edit_message_text(
            "📧 *Mode Analyse E-mail*\n\n"
            "Envoyez-moi l'adresse e-mail à vérifier (ex: `exemple@domaine.com`).",
            parse_mode="Markdown",
        )
    elif query.data == "btn_news":
        news_text = (
            "📢 *Dernières Fuites & Piratages Majeurs*\n\n"
            "🔴 *France Travail* (43M d'usagers)\n"
            "🔴 *Free / Iliad* (19M d'abonnés)\n"
            "🔴 *Ticketmaster* (560M clients)\n"
            "🔴 *Viamedis & Almerys* (33M de personnes)"
        )
        await query.edit_message_text(
            news_text,
            parse_mode="Markdown",
            reply_markup=get_main_keyboard(),
        )
    elif query.data == "btn_stats":
        m = get_all_metrics()
        stats_text = (
            "📊 *Statistiques du Bot*\n\n"
            f"👤 *Mots de passe analysés :* {m.get('tests_mdp', 0)}\n"
            f"   └ 🟢 Forts : {m.get('mdp_forts', 0)}\n"
            f"   └ 🟠 Moyens : {m.get('mdp_moyens', 0)}\n"
            f"   └ 🔴 Faibles : {m.get('mdp_faibles', 0)}\n"
            f"   └ 🚨 Compromis : {m.get('mdp_compromis', 0)}\n\n"
            f"📧 *E-mails contrôlés :* {m.get('tests_email', 0)}\n"
            f"   └ 🚨 Compromis : {m.get('emails_compromis', 0)}"
        )
        await query.edit_message_text(
            stats_text,
            parse_mode="Markdown",
            reply_markup=get_main_keyboard(),
        )


async def handle_message(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    text = update.message.text.strip()
    user_id = update.effective_user.id
    current_state = context.user_data.get("state")

    if current_state == "AWAITING_EMAIL" or re.match(
        r"^[\w\.-]+@[\w\.-]+\.\w+$", text
    ):
        await update.message.reply_text(
            "🔎 *Analyse de l'adresse e-mail en cours...*",
            parse_mode="Markdown",
        )
        is_pwned, breaches = EmailBreachEvaluator.check_breaches(text)
        increment_metric("tests_email")

        if is_pwned:
            increment_metric("emails_compromis")
            log_event(user_id, "EMAIL_TEST", "Compromised")
            breaches_fmt = "\n".join([f"• `{b}`" for b in breaches])
            msg = f"🚨 *ALERTE FUITE DE DONNÉES*\n\nL'adresse `{text}` est présente dans des fuites :\n{breaches_fmt}"
        elif is_pwned is False:
            log_event(user_id, "EMAIL_TEST", "Clean")
            msg = f"🎉 *Aucune fuite détectée pour* `{text}`."
        else:
            msg = "⚠️ Erreur lors de la vérification."

        context.user_data["state"] = None
        await update.message.reply_text(
            msg, parse_mode="Markdown", reply_markup=get_main_keyboard()
        )
    else:
        level, score_pct, criteria = PasswordSecurityEvaluator.evaluate(text)
        pwned_count = PasswordSecurityEvaluator.check_hibp_pwned(text)

        increment_metric("tests_mdp")
        if level == "Fort":
            increment_metric("mdp_forts")
        elif level == "Moyen":
            increment_metric("mdp_moyens")
        else:
            increment_metric("mdp_faibles")

        if pwned_count and pwned_count > 0:
            increment_metric("mdp_compromis")

        log_event(user_id, "PASSWORD_TEST", f"Level: {level}")
        emoji_level = (
            "🟢" if level == "Fort" else ("🟠" if level == "Moyen" else "🔴")
        )

        crit_str = "".join(
            [
                f"{'✅' if c.is_met else '❌'} {c.description}\n"
                for c in criteria
            ]
        )
        pwned_str = (
            f"🚨 Présent {pwned_count:,} fois dans des fuites !"
            if pwned_count
            else "✅ Non détecté dans des fuites."
        )

        msg = f"🔑 *Audit Mot de Passe*\n\nNiveau : {emoji_level} *{level}* ({score_pct:.0f}%)\n\n*Critères :*\n{crit_str}\n{pwned_str}"
        context.user_data["state"] = None
        await update.message.reply_text(
            msg, parse_mode="Markdown", reply_markup=get_main_keyboard()
        )


# ==========================================
# 5. EXECUTION MULTI-THREAD POUR STREAMLIT
# ==========================================


def run_telegram_bot():
    if not TELEGRAM_BOT_TOKEN:
        logger.error("Aucun Token Telegram renseigné.")
        return

    # Boucle Asyncio dédiée au thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CallbackQueryHandler(button_click_handler))
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
    )

    logger.info("Bot Telegram en cours de démarrage...")

    # Lancement étape par étape pour compatibilité Streamlit Threading
    try:
        loop.run_until_complete(app.initialize())
        loop.run_until_complete(app.start())
        loop.run_until_complete(
            app.updater.start_polling(drop_pending_updates=True)
        )
        loop.run_forever()
    except Exception as e:
        logger.error(f"Erreur d'exécution du bot : {e}")


# Lancement unique au premier chargement de la session
if "bot_started" not in st.session_state:
    if TELEGRAM_BOT_TOKEN:
        thread = threading.Thread(target=run_telegram_bot, daemon=True)
        thread.start()
        st.session_state["bot_started"] = True

# ==========================================
# 6. INTERFACE STREAMLIT DASHBOARD
# ==========================================
st.set_page_config(
    page_title="CyberShield Dashboard", page_icon="🛡️", layout="wide"
)

st.title("🛡️ CyberShield - Dashboard Bot Telegram")

if not TELEGRAM_BOT_TOKEN:
    st.error(
        "⚠️ Le token Telegram n'est pas configuré. Rendez-vous dans les Secrets Streamlit pour l'ajouter."
    )
else:
    st.success("🟢 Bot Telegram CyberShield en cours d'exécution en arrière-plan.")

st.markdown("---")

metrics = get_all_metrics()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Mots de passe testés", metrics.get("tests_mdp", 0))
col2.metric("Mots de passe compromis", metrics.get("mdp_compromis", 0))
col3.metric("E-mails contrôlés", metrics.get("tests_email", 0))
col4.metric("E-mails compromis", metrics.get("emails_compromis", 0))

st.markdown("---")

st.subheader("📊 Répartition de la robustesse des mots de passe")
c1, c2, c3 = st.columns(3)
c1.metric("🟢 Forts", metrics.get("mdp_forts", 0))
c2.metric("🟠 Moyens", metrics.get("mdp_moyens", 0))
c3.metric("🔴 Faibles", metrics.get("mdp_faibles", 0))

if st.button("🔄 Rafraîchir les métriques"):
    st.rerun()
    