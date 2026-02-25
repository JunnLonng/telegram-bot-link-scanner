# Security Engine: Technical Documentation

## 1. File Structure
The logic sits primarily in `tools/security_engine.py`. This file consolidates URL validation and relies on external integrations strictly defined inside the `tools/` directory. It uses `Levenshtein` algorithms alongside `urlscan.io` and `VirusTotal` REST API wrappers powered natively by `requests`.

## 2. Dependencies required
To power the logic appropriately, the host must install the following:
```bash
pip install -r requirements.txt
```

## 3. Function Signatures & Tiers

### `class SecurityEngine`
Manages configuration and initialization of external API services. 

#### `def __init__(self, vt_api_key=None, urlscan_api_key=None):`
Sets up API clients for external reputation queries parsing explicitly from the local `.env` backend.
Loads the whitelist database to be cached in memory (performance boost).

#### `def analyze_url(self, url: str) -> dict:`
The primary entrypoint. Takes a URL and returns a diagnostic blob.

#### Normalization Methods: `_de_shorten(url)` & `_normalize(url)`
`_de_shorten` issues an `HTTP HEAD` or `GET` request to resolve the URL. Returns the `response.url`.
`_normalize` uses `urllib.parse` to extract `netloc`, slices deep trailing paths, lowercases the domain, and strips standard subdomains (`www.`).

#### Tier 1 Methods: `check_local_intel(url)` inside `check_local_intel.py`
Uses local blacklist (`local_blacklist_domains.txt`) to execute zero-latency blocks. It also triggers `check_blacklist_domain.py` and `check_blacklist_ip.py` to scrape the Phishing Database (credits to Phishing.Database) via REST dynamically, alongside raw IP matching.

#### Tier 2 Methods: `check_heuristics(domains_to_check)` inside `heuristic_check.py`
- **`calculate_entropy(domain)` & `calculate_vowel_density(domain)`**: Computes Shannon entropy combined mathematically against vowel presence. High >0.82 entropy with extreme <10-20% vowels explicitly triggers DGA detection flags.
- **`check_lookalike(domain, whitelist)`**: Prioritizes substring checks targeting length >4 characters for complex embedding, before computing natively `Levenshtein.distance(str1, str2)`. Flags distances against top-tier Singaporean government brands and commercial bodies parsed locally from `update_whitelist.py`.
- **`tld_risk(tld)`**: Block-matching against `.zip`, `.click`, `.xyz`, etc.

#### Tier 3 Methods: `check_virustotal()` & `check_urlscan_io()`
Requires API keys inside the `.env` configuration mapping. REST queries parse JSON arrays for flagged behaviors, malicious tagging strings, and missing endpoint statuses (404/Timeout bounds handled iteratively).

## 4. Output Formatting
The function returns a `dict` structured identically below:
```json
{
    "verdict": "Suspicious",
    "reasoning": [
        "Tier 2: TLD .xyz is highly suspicious.",
        "Tier 2: Domain entropy indicates an algorithm-generated name."
    ],
    "action": "Do not enter credentials. Verify the source of the message."
}
```
This dictionary is directly formatted and relayed by the Telegram Bot interface.
