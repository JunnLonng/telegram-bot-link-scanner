# Telegram Link Scanner Bot

Instead of copy pasting links to online URL scanners or risking entering unverified links, here is a Telegram bot to protect users from malicious links without having to move between Telegram and online URL scanners.

The bot can be added to any Telegram group chat and will actively scan URLs in Telegram group chats or can be used as a private bot to scan URLs by forwarding messages containing URLs to the bot. It then generates an instant risk verdict (`Safe`, `Suspicious`, or `Dangerous`) with explainable reasoning.

---

## Core Features

- **Scraping registered domains and Singapore Government trusted sites:** Using BeautifulSoup to crawl Singapore Government Directories (SGDI/MAS/Gov.sg) and builds a whitelist to detect typosquatting attempts against Singapore Government trusted sites. An initial whitelist will be generated on the first run, then updates itself every 24 hours. The whitelist also contains some of the famous global companies' domains that are commonly used in phishing attacks. 
- **Check for Typosquatting:** Checks for typosquatting attempts against the whitelist.
- **Check for Domain Generation Algorithm (DGA):** Using entropy and vowel density constraints to detect DGA (e.g. 'xxxxasdad1-moh-gov-sg.com')
- **Cross-check with Global Threat Intelligence:** Validate the URLs against `VirusTotal` & `urlscan.io` using the free tier API keys.

---

## The 3-Tier Security Engine

### 1. Tier 1: Local Intelligence
Check the URL against the local blacklist and `Phishing.Database`. Also checks if the URL is a raw IP address since Raw IP addresses are frequently used in malicious attacks because they allow attackers to evade domain-based filters, conceal their identity behind cheap or compromised infrastructure, and directly target server vulnerabilities
Credits to [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) for the huge data of phishing domains.

### 2. Tier 2: Heuristic "DNA" Analysis
- **Similarity Mapping:** Computes embedded substring matches and native Levenshtein Distance ratios against the whitelist to detect possible brand impersonation.
- **Entropy & Vowel Density Constraints:** Computes Shannon entropy with vowel-density. Flags domains with high entropy boundaries and extremely low vowels (<10-20%) to identify possible Domain Generation Algorithm (DGA) clusters.

### 3. Tier 3: Global API Reputation
Validates remaining unknown URLs against `VirusTotal` & `urlscan.io`. If any Threat Intelligence framework reports malicious activity, the engine adds the domain into the local blacklist for future protection. This will shorten the time taken to scan unknown URLs as well as reduce the consumption of API credits.

---

## Installation & Setup

**1. Clone the repository:**
```bash
git clone https://github.com/JunnLonng/telegram-bot-link-scanner
cd telegram-bot-link-scanner
```

**2. Install dependencies:**
```bash
pip install -r requirements.txt
```

**3. Configure Environment Variables:**
Rename the enclosed `.env.example` file to `.env` (or create a new `.env` file) and supply your highly sensitive system tokens safely:
```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here
```

The Telegram can still function without the API keys, but it will not be able to validate the URLs against `VirusTotal` & `urlscan.io`. You can get the API keys from [VirusTotal](https://www.virustotal.com/) and [urlscan.io](https://urlscan.io/) by registering an account.

**4. Run the bot:**
```bash
python main.py
```

---

## Documentation
You may review the documentations below for more details:
* **[Planning & Concept](docs/planning_and_conceptual.md)**
* **[Technical Documentation](docs/technical_documentation.md)**
