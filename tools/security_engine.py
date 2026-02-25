import os
import urllib.parse
import logging
import requests

from tools.local_intel_check import check_local_intel, add_to_local_blacklist
from tools.heuristic_check import check_heuristics
from tools.check_VT import check_virustotal
from tools.check_urlscan_io import check_urlscan_io

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityEngine:
    def __init__(self, vt_api_key=None, urlscan_api_key=None):
        self.vt_api_key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.urlscan_api_key = urlscan_api_key or os.getenv("URLSCAN_API_KEY")

    def analyze_url(self, url: str) -> dict:
        """
        Main entrypoint to run the tier checks.
        Returns:
            {
                "verdict": "Safe" | "Suspicious" | "Dangerous",
                "risk_score": 0-100,
                "reasoning": [...list of strings...],
                "action": "..."
            }
        """
        score = 0
        reasoning = []
        action = "Safe to proceed"
        verdict = "Safe"
        
        # Resolve any short links and normalise domains
        final_url = self._de_shorten(url)
        original_domain = self._normalize(url)
        final_domain = self._normalize(final_url)
        
        domains_to_check = {original_domain}
        if final_domain and final_domain != original_domain:
            domains_to_check.add(final_domain)

        urls_to_check = {url}
        if final_url != url:
            urls_to_check.add(final_url)
            
        # Check if URL forces HTTP and refuses HTTPS
        if url.startswith("http://"):
            try:
                https_url = "https://" + url[7:]
                requests.head(https_url, timeout=3)
            except Exception:
                score += 40
                reasoning.append("Site refuses secure HTTPS connections and runs only on HTTP (Elevated risk).")
            
        # ---------------------------------------------------------------------
        # TIER 1: LOCAL INTELLIGENCE (BLACKLIST CHECKS)
        # ---------------------------------------------------------------------
        is_blacklisted, b_type, t1_messages = check_local_intel(url, final_url, domains_to_check)
        if is_blacklisted:
            score += 100
            for msg in t1_messages:
                if msg not in reasoning:
                    reasoning.append(msg)

        # ---------------------------------------------------------------------
        # TIER 2: HEURISTIC "DNA" ANALYSIS (AGAINST WHITELIST)
        # ---------------------------------------------------------------------
        tier2_suspicious, t2_score, t2_messages = check_heuristics(domains_to_check)
        score += t2_score
        for msg in t2_messages:
            if msg not in reasoning:
                reasoning.append(msg)

        # ---------------------------------------------------------------------
        # TIER 3: GLOBAL API REPUTATION (VIRUSTOTAL & URLSCAN.IO)
        # ---------------------------------------------------------------------
        # No requirement to check global scans if already flagged 100% in Tier 1 blacklist
        if not is_blacklisted:
            global_malicious_flag = False
            vt_failed = False
            urlscan_failed = False
            
            # --- VIRUSTOTAL CHECK ---
            if self.vt_api_key:
                for u in urls_to_check:
                    is_malicious, vt_msg = check_virustotal(u, self.vt_api_key)
                    if is_malicious:
                        global_malicious_flag = True
                        score = max(score, 100) # Ensure score is at least 100
                        if vt_msg and vt_msg not in reasoning:
                            reasoning.append(vt_msg)
                        
                        # Add domain to local backend if flagged
                        for d in domains_to_check:
                            add_to_local_blacklist(d)
                            add_msg = f"Added '{d}' to local blacklist based on VirusTotal."
                            if add_msg not in reasoning:
                                reasoning.append(add_msg)
                        break
                    elif vt_msg:
                        if "error" in vt_msg.lower() or "failed" in vt_msg.lower():
                            vt_failed = True
                        if vt_msg not in reasoning:
                            reasoning.append(vt_msg)
            else:
                logger.warning("Tier 3: VirusTotal API key not found. Skipping VT check.")
                reasoning.append("Tier 3: VirusTotal API key not found. Skipping VT check.")
                vt_failed = True
                
            # --- URLSCAN.IO CHECK ---
            # Don't bother scanning if VT already proved it's purely malicious
            if self.urlscan_api_key and not global_malicious_flag:
                for u in urls_to_check:
                    is_malicious, urlscan_msg = check_urlscan_io(u, self.urlscan_api_key)
                    
                    if is_malicious:
                        score = max(score, 100) 
                        if urlscan_msg and urlscan_msg not in reasoning:
                            reasoning.append(urlscan_msg)
                            
                        # Add domain to local backend if flagged
                        for d in domains_to_check:
                            add_to_local_blacklist(d)
                            add_msg = f"Added '{d}' to local blacklist based on urlscan.io."
                            if add_msg not in reasoning:
                                reasoning.append(add_msg)
                        break
                    elif urlscan_msg:
                        if "error" in urlscan_msg.lower() or "failed" in urlscan_msg.lower() or "blocked or invalid" in urlscan_msg.lower() or "timed out" in urlscan_msg.lower():
                            urlscan_failed = True
                        if urlscan_msg not in reasoning:
                            reasoning.append(urlscan_msg)
            elif not self.urlscan_api_key:
                logger.warning("Tier 3: Urlscan.io API key not found. Skipping scan.")
                reasoning.append("Tier 3: Urlscan.io API key not found. Skipping urlscan check.")
                urlscan_failed = True
                
            if vt_failed and urlscan_failed:
                score = max(score, 40)
                reasoning.append("Tier 3: External sources could not verify the link (API blocking / Not Found). Treat with heightened caution.")

        # Final Evaluation
        final_score = min(score, 100)
        
        if final_score >= 80:
            verdict = "Dangerous"
            action = "Highly unsafe. Do not visit this site or interact with the link. Do not enter credentials or download files."
        elif final_score >= 40:
            verdict = "Suspicious"
            action = "Exercise strong caution. Check the link source carefully before interacting."
        else:
            verdict = "Safe"
            action = "Site appears safe."

        # If it wasn't strictly clean and we accrued no reasons
        if not reasoning and final_score < 40:
            reasoning.append("No significant threats detected across all tiers.")

        return {
            "verdict": verdict,
            "risk_score": final_score,
            "reasoning": reasoning,
            "action": action
        }

    def _de_shorten(self, url):
        """Resolves redirects."""
        try:
            resp = requests.head(url, allow_redirects=True, timeout=5)
            # if the target is unreachable with HEAD, try GET
            if resp.status_code >= 400:
                 resp = requests.get(url, allow_redirects=True, timeout=5)
            return resp.url
        except Exception as e:
            logger.warning(f"De-shorten failed for {url}: {e}")
            return url

    def _normalize(self, url):
        """Extracts netloc and strips www."""
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        netloc = netloc.split(':')[0].lower() # remove ports
        
        # Remove www.
        if netloc.startswith("www."):
            netloc = netloc[4:]
            
        return netloc
