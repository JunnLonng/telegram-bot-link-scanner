import os
import re
import telebot
from dotenv import load_dotenv

from tools.security_engine import SecurityEngine
from tools.check_if_url_exists import extract_url, check_url_type, process_missing_schema_url

bot = None
engine = None

def setup_environment():
    """Loads environment variables and retrieves the Telegram bot token."""
    load_dotenv()
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    
    if not token:
        print("CRITICAL: TELEGRAM_BOT_TOKEN is not set in your .env file.")
        print("Please add it and run the bot again.")
        print("Example: TELEGRAM_BOT_TOKEN=your_token_here")
        exit(1)
        
    return token

def initialize_components(token):
    """Initializes the global Telegram bot and Security Engine instances."""
    global bot, engine
    bot = telebot.TeleBot(token)
    print("Initializing Security Engine. Checking connections...")
    engine = SecurityEngine()
    print("Security Engine is ready.")

def format_analysis_result(url, result):
    """Formats the security engine JSON result into a readable Markdown string."""
    verdict = result.get('verdict', 'Unknown')
    reasons = result.get('reasoning', [])
    action = result.get('action', 'Be careful')
    
    if verdict == "Safe":
        icon = "✅"
    elif verdict == "Suspicious":
        icon = "⚠️"
    else:
        icon = "⛔️"
        
    reply_lines = [
        f"🌐 **Target**: `{url}`",
        f"{icon} **Verdict**: {verdict}\n",
        "**Reasoning**:"
    ]
    
    has_heightened_caution = any("External sources could not verify the link" in r for r in reasons)
    
    for reason in reasons:
        if has_heightened_caution:
            if "urlscan.io scan blocked" in reason or "VirusTotal API error" in reason or "urlscan.io submission error" in reason or "failed or timed out" in reason:
                continue
                
        # Cleanly remove "Tier X:" or "Tier X (Name):" prefixes
        clean_reason = re.sub(r'^Tier\s+\d+.*?:\s+', '', reason, flags=re.IGNORECASE)
        reply_lines.append(f"• {clean_reason}")
        
    reply_lines.append(f"\n**Action**: {action}")
    
    return "\n".join(reply_lines)

def handle_inactive_url(message, url, reply_to_mode=False):
    """Handles logic for URLs that fail name resolution (inactive/dead links)."""
    global bot, engine
    
    try:
        # Run the full heuristic analysis engine on the non-resolving domain
        result = engine.analyze_url(url)
        
        
        # Explicit note about the offline status
        result['reasoning'].append("Domain is currently offline / does not resolve to an IP address.")
        
        if result['verdict'] == "**Dangerous**":
            result['action'] = "**Domain is dangerous but inactive. Do not interact with it.**"
        elif result['verdict'] == "**Suspicious**":
            result['reasoning'].append("Detected **suspicious patterns** in this URL (e.g., unusual characters or brand imitation). Although the site is currently offline, these patterns are common in **phishing attacks**.")
            result['action'] = "Exercise **strong caution**."
        else:
            result['action'] = "Domain is offline. Suggest to check again later when the site is back online."
            
        formatted_reply = format_analysis_result(url, result)
        
        if reply_to_mode:
            bot.reply_to(message, formatted_reply, parse_mode="Markdown")
        else:
            bot.send_message(message.chat.id, formatted_reply, parse_mode="Markdown")
            
    except Exception as e:
        error_msg = f"❌ An error occurred while analyzing `{url}`: {str(e)}"
        if reply_to_mode:
            bot.reply_to(message, error_msg, parse_mode="Markdown")
        else:
            bot.send_message(message.chat.id, error_msg)

def process_message(message):
    """Main orchestration function to extract, validate, and analyze URLs in a message."""
    global bot, engine
    text = message.text or ""
    url = extract_url(text)
    
    if not url:
        return # Silently skip messages without URLs to avoid spamming groups
        
    status, final_url = check_url_type(url)
    
    if status == "missing_schema":
        loading_msg = bot.reply_to(
            message, 
            f"⚠️ **Missing scheme (https:// or http://) detected for** `{url}`\n"
            "I will attempt to auto-fix and scan for both `http://` and `https://`..."
        )
        process_missing_schema_url(bot, message, url, loading_msg, engine, handle_inactive_url, format_analysis_result)
        
    elif status == "name_resolution_error":
        handle_inactive_url(message, url, reply_to_mode=True)
        
    else:
        loading_msg = bot.reply_to(
            message, 
            f"🔍 **URL detected**: `{url}`\n⏳ Analyzing with Security Logic Engine, please wait..."
        )
        try:
            result = engine.analyze_url(url)
            formatted_reply = format_analysis_result(url, result)
            
            # When missing schema formatting isn't required, edit the initial status message to be clean
            reply_lines = formatted_reply.split('\n')
            formatted_reply_no_target = "\n".join(reply_lines[1:])
            
            bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=loading_msg.message_id,
                text=formatted_reply_no_target, 
                parse_mode="Markdown"
            )
        except Exception as e:
            bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=loading_msg.message_id,
                text=f"❌ An error occurred while analyzing the URL: {str(e)}"
            )

def register_telebot_handlers():
    """Registers the necessary Telegram handlers for command reception."""
    global bot
    @bot.message_handler(commands=['start', 'help'])
    def send_welcome(message):
        bot.reply_to(
            message,
            "👋 Welcome to the **Link Scanner Bot**!\n\n"
            "Feel free to forward messages containing a URL; I'll scan the URL automatically!\n\n"
            "For more information on how this bot works, please refer to [GitHub Repository](https://github.com/JunnLonng/telegram-bot-link-scanner)."
            ,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )

    @bot.message_handler(func=lambda message: True)
    def analyze_incoming_message(message):
        process_message(message)
