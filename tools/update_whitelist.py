import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

import re
import os
def get_domains_from_url(base_url, href):
    """
    Helper to extract valid domains from a relative or absolute URL.
    Returns a list of domain strings.
    """
    if href.startswith(('javascript:', 'mailto:', 'tel:')):
        return []
        
    domain_pattern = r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    found_domains = re.findall(domain_pattern, href)
    
    invalid_tlds = {'html', 'htm', 'php', 'aspx', 'jsp', 'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'xml', 'ashx'}
    
    valid_domains = []
    for d in found_domains:
        d = d.lower().rstrip('.')
        tld = d.split('.')[-1]
        if tld not in invalid_tlds:
            if d not in valid_domains:
                valid_domains.append(d)
                
    # Also include standard netloc just in case
    full_url = urljoin(base_url, href)
    parsed = urlparse(full_url)
    if parsed.netloc:
        netloc_domain = parsed.netloc.split(':')[0].lower().rstrip('.')
        if re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', netloc_domain):
            if netloc_domain not in valid_domains:
                valid_domains.append(netloc_domain)
            
    return valid_domains

def get_page_domains(url):
    """
    Fetches a page and returns a set of unique domains found in <a> tags.
    Optionally filters for .gov.sg domains.
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        domains = set()
        
        for a_tag in soup.find_all('a', href=True):
            extracted_domains = get_domains_from_url(url, a_tag['href'])
            for domain in extracted_domains:
                domains.add(domain)
        return domains
    except Exception as e:
        print(f"Error scraping {url}: {e}")
        return set()

def update_whitelist_from_sgdi():
    base_urls = [
        "https://www.sgdi.gov.sg/ministries",
        "https://www.sgdi.gov.sg/statutory-boards",
        "https://www.sgdi.gov.sg/organs-of-state"
    ]
    
    # Helper to get full URLs for navigation
    def get_full_urls(page_url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(page_url, headers=headers, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()
            for a in soup.find_all('a', href=True):
                full = urljoin(page_url, a['href'])
                links.add(full)
            return links
        except:
            return set()

    all_target_pages = []
    
    for url in base_urls:
        print(f"Starting crawl at {url}...")
        links = get_full_urls(url)
        # We look for links that match the category being crawled
        section_id = url.split('/')[-1]
        section_pages = [link for link in links if f"/{section_id}/" in link]
        all_target_pages.extend(section_pages)
        
    unique_pages = list(set(all_target_pages))
    print(f"Found {len(unique_pages)} SGDI entity pages to scan.")
    
    all_whitelisted_domains = set()
    
    # Visit each entity page
    for i, page_url in enumerate(unique_pages):
        print(f"[{i+1}/{len(unique_pages)}] Scanning {page_url}...")
        domains_on_page = get_page_domains(page_url)
        all_whitelisted_domains.update(domains_on_page)
        
    return list(all_whitelisted_domains)

def update_whitelist_from_gov_trusted():
    url = "https://www.gov.sg/trusted-sites/"
    print(f"Starting crawl at {url}...")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        domains = set()
        domain_pattern = r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        
        # Look for explicit links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('http') or href.startswith('www.'):
                parsed = urlparse(href if href.startswith('http') else 'https://' + href)
                if parsed.netloc:
                    netloc = parsed.netloc.split(':')[0].lower()
                    if netloc.startswith('www.'):
                        netloc = netloc[4:]
                    if netloc and '.' in netloc:
                        domains.add(netloc)
                        
        # Look for plain text mentions
        page_text = soup.get_text()
        found_in_text = re.findall(domain_pattern, page_text)
        invalid_tlds = {'html', 'htm', 'php', 'aspx', 'jsp', 'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf'}
        
        for d in found_in_text:
            d = d.lower().rstrip('.')
            tld = d.split('.')[-1]
            if tld not in invalid_tlds and 'gov.sg' in d:
               if d.startswith('www.'):
                   d = d[4:]
               domains.add(d)

        print(f"Found {len(domains)} trusted sites.")
        return list(domains)
    except Exception as e:
        print(f"Error crawling {url}: {e}")
        return []

def update_whitelist_from_mas():
    mas_url = "https://eservices.mas.gov.sg/fid/institution?count=0"
    print(f"Starting crawl at {mas_url}...")
    # Using filter_gov_sg=False because banks are commercial (e.g. dbs.com, uob.com)
    # But we might want to apply some other validation or trust purely what's on MAS site.
    # For now, let's grab all domains linked from the main listing.
    
    # Note: The MAS directory page might modify content via JS or pagination.
    # We will try a simple static scrape first.
    return list(get_page_domains(mas_url))

def update_whitelist():
    print("Starting automated whitelist update...")
    sgdi_domains = update_whitelist_from_sgdi()
    gov_trusted_domains = update_whitelist_from_gov_trusted()
    mas_domains = update_whitelist_from_mas()
    
    GLOBAL_COMPANIES = [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com", "github.com"
    ]
    
    HIGH_PROFILE_BRANDS = [
        "dbs.com", "uob.com.sg", "ocbc.com", "google.com", "microsoft.com", 
        "apple.com", "amazon.com", "facebook.com", "instagram.com", "paypal.com"
    ]
    
    all_domains = set(sgdi_domains + gov_trusted_domains + mas_domains + GLOBAL_COMPANIES + HIGH_PROFILE_BRANDS)
    
    print(f"\nTotal unique domains found: {len(all_domains)}")
    print(f"(SGDI: {len(sgdi_domains)}, Gov Trusted: {len(gov_trusted_domains)}, MAS: {len(mas_domains)})")
    
    whitelist_path = os.path.join(os.path.dirname(__file__), "local_whitelist_domains.txt")
    with open(whitelist_path, "w", encoding="utf-8") as f:
        for domain in sorted(all_domains):
            f.write(domain + "\n")
    print(f"Domains successfully saved to {whitelist_path}")

def periodic_whitelist_update(engine):
    """Background task to periodically pull updates to the heuristic whitelist."""
    import time
    while True:
        try:
            update_whitelist()
        except Exception as e:
            print(f"Periodic whitelist update failed: {e}")
        time.sleep(86400) # Sleep for 24 hours

if __name__ == "__main__":
    update_whitelist()