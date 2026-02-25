# Link Security Engine: Planning and Conceptual Document

## 1. Overview
The "Security Logic Engine" is the core analytical processing module for the Telegram bot. Its purpose is to evaluate incoming URLs and their associated messages to assess potential security threats (e.g., phishing, malware, scams). The evaluation generates a structured Risk Score (0-100), a human-readable Verdict (`Safe`, `Suspicious`, or `Dangerous`), and an actionable insight based on a rigorous 5-Tier Scanning Process.

## 2. Objectives
- **Accuracy**: Minimize false positives and false negatives by evaluating URLs comprehensively.
- **Efficiency**: Avoid unnecessary API calls to rate-limited services (like VirusTotal and urlscan.io) by front-loading lightweight, high-fidelity checks.
- **Explainability**: Provide the user with a clear, step-by-step reasoning behind the rating, explaining _why_ a link was deemed unsafe.

## 3. The 3-Tier Scanning Process
Before analysis begins, the engine resolves and normalizes incoming URLs:
- **De-shorten**: Automatically follow URL redirects (e.g., `bit.ly`, `t.co`) to reveal the final destination.
- **Normalize**: Parse the root domain by stripping protocols (`https://`, `http://`), ports, and prefixes (`www.`).
- **HTTPS Enforcement Check**: Penalizes URLs that only operate on insecure HTTP and refuse HTTPS connections.

### Tier 1: Local Intelligence
We rely on updated, open-source local lists.
- **Local Blacklist Cache**: Checks domains natively blocked during previous malicious external scans to execute zero-latency blocks.
- **Global Phishing Blacklist**: Check against a known list of active phishing domains/IPs (e.g., Phishing.Database). If matched, assign Risk Score: 100 and cast **Dangerous** verdict.
- **IP Check**: Check whether the URL connects directly via a raw IP address instead of an alphanumeric domain. Since legitimate modern services rarely use raw IPs publicly, this carries immediately high risk.

### Tier 2: Heuristic "DNA" Analysis
Focuses on intrinsic properties of the domain string that may indicate malicious intent.
- **Similarity (Levenshtein Distance)**: Computes embedded substring matches and look-alike attributes against dynamically updated whitelist brands (e.g., Singaporean Ministries & Global Tech). Detects typosquatting (e.g., `1ras.gov.sg` instead of `iras.gov.sg`).
- **TLD Risk**: Evaluates the Top Level Domain. Extensions like `.zip`, `.click`, `.xyz`, or `.top` hold statistically higher probabilities of abuse.
- **Entropy & Density**: Computes the Shannon entropy paired with Vowel-Density calculations. Flags strings with high entropy boundaries and extremely low vowels (<10-20%), accurately identifying machine-generated Domain Generation Algorithm (DGA) strings (e.g., `szvkr-pl0x.com`).

### Tier 3: Global API Reputation
If the URL is suspicious locally, consult major international security vendors like VirusTotal and urlscan.io via API.
- **Trigger Condition**: If either returns a threat, the URL is marked **Dangerous**, and the domain is forcefully added to the Local Blacklist. If both external APIs fail due to blocked/DNS timeouts, it elevates the risk profile to **Suspicious** to warn users of potential risk.

## 4. Expected Outcomes
- **Verdict**: [Safe | Suspicious | Dangerous]
- **Reasoning**: A bulleted explanation stating precisely which tiers identified the red flag(s).
- **Action**: A short, actionable insight based on the risk profile.
