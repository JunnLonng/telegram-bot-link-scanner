import threading
import telegram_bot
from telegram_bot import setup_environment, initialize_components, register_telebot_handlers
from tools.update_whitelist import periodic_whitelist_update

def main():
    """Primary entry point orchestrating program configuration and polling."""
    print("=========================================")
    print("Telegram Link Scanner Bot is starting...")
    
    # 1. Load telegram bot environment and get token from .env file
    token = setup_environment()
    
    # 2. Initialize Telegram bot engine and SecurityEngine in telegram_bot.py
    initialize_components(token)
    
    # 3. Register message handlers in telegram_bot.py
    register_telebot_handlers()
    
    # 4. Start the periodic whitelist updater in the background
    threading.Thread(
        target=periodic_whitelist_update, 
        args=(telegram_bot.engine,), 
        daemon=True
    ).start()
    
    print("Listening for incoming messages...")
    print("=========================================")
    
    # Enable background polling to listen dynamically
    telegram_bot.bot.infinity_polling()

if __name__ == "__main__":
    main()