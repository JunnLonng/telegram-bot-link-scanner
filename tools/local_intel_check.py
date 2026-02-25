import os
import re
from tools.check_blacklist_domain import check_blacklist as check_blacklist_domain
from tools.check_blacklist_ip import check_ip as check_blacklist_ip
def check_local_blacklist(domain, url):
    local_blacklist_path = os.path.join(os.path.dirname(__file__), "local_blacklist_domains.txt")
    if os.path.exists(local_blacklist_path):
        try:
            with open(local_blacklist_path, "r", encoding="utf-8") as f:
                for line in f:
                    blacklisted_item = line.strip().lower()
                    if blacklisted_item == domain.lower() or blacklisted_item == url.lower():
                        return True
        except Exception as e:
            return False
    return False

def add_to_local_blacklist(domain):
    local_blacklist_path = os.path.join(os.path.dirname(__file__), "local_blacklist_domains.txt")
    try:
        # Check if already exists
        if os.path.exists(local_blacklist_path):
            with open(local_blacklist_path, "r", encoding="utf-8") as f:
                if any(domain.lower() == line.strip().lower() for line in f):
                    return # Already in blacklist

        with open(local_blacklist_path, "a", encoding="utf-8") as f:
            f.write(domain + "\n")
    except Exception as e:
        print(f"Error adding to local blacklist: {e}")

def check_local_intel(url, final_url, domains_to_check):
    """
    Tier 1 check: 
    1. Checks local blacklist (local_blacklist_domains.txt)
    2. Checks external blacklist (Phishing Database) via check_blacklist.py
    3. Checks if it navigates directly to an IP
    """
    messages = []
    
    urls_to_check = {url}
    if final_url != url:
        urls_to_check.add(final_url)
        
    for u in urls_to_check:
        domain = u.split("//")[-1].split("/")[0] # basic parsing for local check
        
        # Check local blacklist
        if check_local_blacklist(domain, u):
            messages.append(f"Tier 1: Matched local blacklist.")
            return True, "Local", messages

        # Check external blacklist (Domain)
        is_blacklisted, b_type = check_blacklist_domain(u)
        if is_blacklisted:
            messages.append(f"Tier 1: Matched Phishing.Database Blacklist ({b_type}).")
            return True, b_type, messages

        # Check external blacklist (IP)
        if check_blacklist_ip(domain):
            messages.append("Tier 1: Matched Phishing.Database IP Blacklist.")
            return True, "IP", messages
            
    # Check for raw IP
    ipv4_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    for d in domains_to_check:
        if re.match(ipv4_pattern, d):
            msg = f"Tier 1: URL navigates directly to a raw IP address."
            if msg not in messages: messages.append(msg)
            return True, "IP", messages
            
    return False, None, messages
