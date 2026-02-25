import requests

#this function will check if the link provided is in the blacklist
#blacklist database is from Phishing.Database (GitHub)
def check_blacklist(link):
    blacklist_db_url = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt"
    
    try:
        response = requests.get(blacklist_db_url)
        if response.status_code == 200:
            blacklist = response.text.splitlines()
        else:
            print(f"Error: {response.status_code}")
            return False, None
        if "//" in link:
            domain = link.split("//")[1].split("/")[0]
        else:
            domain = link.split("/")[0]
    except Exception as e:
        print(f"Error: {e}")
        return False, None
    
    #check if the domain is in the blacklist
    try:
        if domain in blacklist:
            return True, "URL"
        else:
            return False, None
    except Exception as e:
        print(f"Error: {e}")
        return False, None