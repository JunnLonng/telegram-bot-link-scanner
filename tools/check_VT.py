import os
import requests
import base64
import logging

logger = logging.getLogger(__name__)

def check_virustotal(url, api_key=None):
    """
    Tier 3 check:
    Uses VirusTotal API v3 to scan the URL.
    Returns (True, message) if flagged malicious or suspicious, else (False, None).
    """
    if not api_key:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
    if not api_key:
        logger.warning("Tier 3: VirusTotal API key not found. Skipping VT check.")
        return False, "Tier 3: VirusTotal API key not found. Skipping VT check."
        
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        resp = requests.get(endpoint, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious >= 2:
                return True, "Tier 3: Flagged maliciously by VirusTotal engines."
            else:
                return False, "Tier 3: Scanned by VirusTotal (Clean)."
        else:
            return False, f"Tier 3: VirusTotal API error ({resp.status_code})."
    except Exception as e:
        logger.error(f"VirusTotal request error: {e}")
        return False, f"Tier 3: VirusTotal request error -> {str(e)}"
        
    return False, "Tier 3: VirusTotal scan failed or timed out."
