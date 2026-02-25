import os
import time
import requests
import logging

logger = logging.getLogger(__name__)

def check_urlscan_io(url, api_key=None):
    """
    Tier 3 check:
    Uses urlscan.io API to scan the URL.
    Returns (True, message) if flagged malicious, else (False, None).
    """
    if not api_key:
        api_key = os.getenv("URLSCAN_API_KEY")
        
    if not api_key:
        logger.warning("Tier 3: urlscan.io API key not found. Skipping check.")
        return False, "Tier 3: urlscan.io API key not found. Skipping check."
        
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    data = {
        "url": url,
        "visibility": "public" # Can be public, unlisted, or private
    }
    
    submit_endpoint = "https://urlscan.io/api/v1/scan/"
    
    try:
        # 1. Submit the URL for scanning
        resp = requests.post(submit_endpoint, headers=headers, json=data)
        
        if resp.status_code == 429:
             return False, "Tier 3: urlscan.io API rate limit exceeded."
             
        if resp.status_code == 400:
             error_msg = resp.json().get("message", "Scan prevented")
             return False, f"Tier 3: urlscan.io scan blocked or invalid ({error_msg})."
             
        if resp.status_code != 200:
             return False, f"Tier 3: urlscan.io submission error ({resp.status_code})."
             
        res_data = resp.json()
        uuid = res_data.get("uuid")
        api_url = res_data.get("api")
        
        if not uuid or not api_url:
             return False, "Tier 3: urlscan.io failed to return an analysis UUID."
             
        # 2. Poll for results
        max_retries = 5
        wait_seconds = 8
        
        for attempt in range(max_retries):
             time.sleep(wait_seconds)
             result_resp = requests.get(api_url, headers=headers)
             
             if result_resp.status_code == 200:
                 result_json = result_resp.json()
                 
                 # Analyze verdict
                 verdicts = result_json.get("verdicts", {})
                 overall = verdicts.get("overall", {})
                 
                 is_malicious = overall.get("malicious", False)
                 tags = overall.get("tags", [])
                 
                 if is_malicious:
                     tag_str = ", ".join(tags) if tags else "malicious activity"
                     return True, f"Tier 3: Flagged maliciously by urlscan.io [{tag_str}]."
                 else:
                     return False, "Tier 3: Scanned by urlscan.io (Clean)."
                     
             elif result_resp.status_code == 404:
                 continue
             else:
                 break
                 
        return False, "Tier 3: urlscan.io scan timed out or is still processing."
        
    except Exception as e:
        logger.error(f"urlscan.io request error: {e}")
        return False, f"Tier 3: urlscan.io error -> {str(e)}"
