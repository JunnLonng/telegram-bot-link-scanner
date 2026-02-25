import math
import os
import re
from Levenshtein import distance

SUSPICIOUS_TLDS = {
    "zip", "click", "xyz", "top", "pw", "cc", "club", "info", "tk", "ml", "ga", "cf", "gq"
}

def load_whitelist():
    """Loads whitelist candidates from local file"""
    # Assuming local_whitelist_domains.txt or whitelist.txt is present
    whitelist_path = os.path.join(os.path.dirname(__file__), "local_whitelist_domains.txt")
    if not os.path.exists(whitelist_path):
        whitelist_path = os.path.join(os.path.dirname(__file__), "whitelist.txt")
    domains = set()
    try:
        if os.path.exists(whitelist_path):
            with open(whitelist_path, "r", encoding="utf-8") as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain:
                        # Strip www.
                        if domain.startswith("www."):
                            domain = domain[4:]
                        domains.add(domain)
    except Exception as e:
        print(f"Error loading whitelist: {e}")
    return domains

def normalize_homoglyphs(domain):
    replacements = {"rn": "m", "cl": "d", "0": "o", "1": "l", "vv": "w", "v": "u"}
    for spoof, real in replacements.items():
        domain = domain.replace(spoof, real)
    return domain

def check_lookalike(domain, whitelist):
    """Returns the brand name if a typo or compound phrasing is found."""
    # Normalize the domain to compare cleanly
    if domain in whitelist:
        return None
        
    base_name = domain.split('.')[0]
    normalized_base = normalize_homoglyphs(base_name)
    
    best_match = None
    best_dist = 999
    longest_substring_match = ""
    
    for brand_domain in whitelist:
        target_base = brand_domain.split('.')[0]
        
        full_brand_flat = brand_domain.replace(".", "")
        normalized_target_base = normalize_homoglyphs(target_base)
        
        if len(full_brand_flat) >= 4 and full_brand_flat in normalized_base.replace("-", "") and len(full_brand_flat) > len(longest_substring_match):
             longest_substring_match = brand_domain
             best_match = brand_domain
             best_dist = 0 # Exact embedded match
             continue
             
        if len(target_base) >= 4 and target_base in normalized_base:
            if len(target_base) > len(longest_substring_match.split('.')[0] if longest_substring_match else ""):
                longest_substring_match = brand_domain
                best_match = brand_domain
        elif len(target_base) == 3:
            # For 3-letter acronyms, only match if it appears as a distinct word (separated by hyphens etc.)
            # or if the word starts with it exactly (e.g. dbsverify)
            words = re.split(r'[^a-z0-9]', normalized_base)
            if target_base in words or normalized_base.startswith(target_base):
                if len(target_base) > len(longest_substring_match.split('.')[0] if longest_substring_match else ""):
                    longest_substring_match = brand_domain
                    best_match = brand_domain
                
        # If it's a pure typo, calculate Levenshtein distance on normalized strings
        dist = distance(normalized_base, normalized_target_base)
        
        # If exactly 0 after normalization, it's a direct homoglyph or TLD swap!
        if dist == 0:
            return brand_domain
            
        # Length-Scaling to Levenshtein
        if len(target_base) <= 3:
            tight_threshold = 0 # 3-letter acronyms require exact embedded match or exact normalized match
        else:
            tight_threshold = 1 if len(target_base) <= 6 else 2
        
        if 0 < dist <= tight_threshold:
            # We only prefer typo distance if we haven't found a direct substring embed yet
            if not longest_substring_match and dist < best_dist:
                best_dist = dist
                best_match = brand_domain
                
    return best_match or longest_substring_match

def calculate_entropy(text):
    """Calculates Shannon entropy."""
    if not text or len(text) <= 1:
        return 0
    entropy = sum(- (float(text.count(x)) / len(text)) * math.log(float(text.count(x)) / len(text), 2) for x in set(text))
    
    # Calculate an 'entropy ratio'
    ideal_entropy = math.log(len(text), 2)
    if ideal_entropy == 0:
        return 0
    return entropy / ideal_entropy # Triggers if > 0.85 or 0.90 for random inputs

def calculate_vowel_density(text):
    """Calculates the percentage of vowels in the string."""
    if not text:
        return 0
    vowels = set("aeiou")
    count = sum(1 for char in text.lower() if char in vowels)
    return count / len(text)

def check_heuristics(domains_to_check):
    """
    Tier 2 check:
    1. Looks for lookalike domains against the whitelist.
    2. Checks for suspicious TLDs.
    3. Calculates Shannon Entropy to catch dynamically generated domains.
    """
    score = 0
    messages = []
    tier2_suspicious = False
    
    whitelist = load_whitelist()
    
    for d in domains_to_check:
        lookalike = check_lookalike(d, whitelist)
        if lookalike:
            score += 40
            msg = f"Tier 2: Typosquatting detected - looks similar to '{lookalike}'."
            if msg not in messages: messages.append(msg)
            tier2_suspicious = True
            
        tld = d.split('.')[-1]
        if tld in SUSPICIOUS_TLDS:
            score += 30
            msg = f"Tier 2: Uses a potentially suspicious TLD (.{tld})."
            if msg not in messages: messages.append(msg)
            tier2_suspicious = True
            
        # Extract the apex domain text (longest chunk between dots) 
        # to ensure we don't accidentally factor in short TLDs
        parts = d.split('.')
        apex_part = max(parts, key=len) if parts else d
            
        ent_ratio = calculate_entropy(apex_part)
        vowel_density = calculate_vowel_density(apex_part)
        
        # High entropy combined with unusually low vowel density strongly suggests Domain Generation Algorithms
        if len(apex_part) >= 8:
            if ent_ratio > 0.82 and vowel_density < 0.20:
                score += 25
                msg = f"Tier 2: High domain name entropy ({ent_ratio:.2f}) with unusually low vowel density ({vowel_density:.2f}), suggesting randomly generated characters (DGA)."
                if msg not in messages: messages.append(msg)
                tier2_suspicious = True
            elif vowel_density < 0.10: # Extreme lack of vowels suggests machine-generated spam string
                score += 25
                msg = f"Tier 2: Extremely low vowel density ({vowel_density:.2f}), suggesting randomly generated characters (DGA)."
                if msg not in messages: messages.append(msg)
                tier2_suspicious = True
            
    return tier2_suspicious, score, messages
