import socket
import requests

def get_blacklist_ip_db():
    try:
        blacklist_db_ip = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-IPs-ACTIVE.txt"
        response = requests.get(blacklist_db_ip)
        if response.status_code == 200:
            blacklist = response.text.splitlines()
            return blacklist
        else:
            print(f"Error: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    
def check_ip(url):
    try:
        ip_address = socket.gethostbyname(url)
        if ip_address:
            blacklist = get_blacklist_ip_db()
            #check if the IP address is in the blacklist
            if ip_address in blacklist:
                return True
            else:
                return False
    except Exception as e:
        print(f"Error: {e}")
        return False


