import re
import requests

def extract_url(text):
    # Regex to find URLs:
    # 1. http/https scheme
    # 2. www. prefix
    # 3. Domain-like text (e.g. bit.ly, sub.domain.com) with optional path
    url_pattern = r'(?:https?://\S+|www\.\S+|[a-zA-Z0-9-]+\.(?:[a-zA-Z0-9-]+\.)*[a-zA-Z]{2,}(?:/\S*)?)'
    
    match = re.search(url_pattern, text)
    if match:
        return match.group(0)
    return None

def check_url_type(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return "valid", response.url
    except requests.exceptions.MissingSchema:
        return "missing_schema", url
    except requests.exceptions.ConnectionError as e:
        error_str = str(e)
        if "NameResolutionError" in error_str or "getaddrinfo" in error_str:
            return "name_resolution_error", url
        return "connection_error", url
    except requests.exceptions.RequestException as e:
        return "error", url

def process_missing_schema_url(bot, message, original_url, loading_msg, engine, handle_inactive_url, format_analysis_result):
    """Handles scenarios where a user sends a URL missing its 'http(s)://' scheme."""
    urls_to_scan = [f"http://{original_url}", f"https://{original_url}"]
    
    for target_url in urls_to_scan:
        current_status, _ = check_url_type(target_url)
        
        if current_status == "name_resolution_error":
            handle_inactive_url(message, target_url, reply_to_mode=False)
            continue
            
        try:
            result = engine.analyze_url(target_url)
            formatted_reply = format_analysis_result(target_url, result)
            bot.send_message(message.chat.id, formatted_reply, parse_mode="Markdown")
        except Exception as e:
            bot.send_message(message.chat.id, f"❌ An error occurred while analyzing `{target_url}`: {str(e)}")
            
    try:
        bot.edit_message_text(
            "✅ No schemas (https:// or http://) detected. I will proceed to scan for both schemas.", 
            chat_id=message.chat.id, 
            message_id=loading_msg.message_id
        )
    except Exception:
        pass