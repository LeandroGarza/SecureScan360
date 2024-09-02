import requests
from bs4 import BeautifulSoup

def find_login_url(targets):
    common_login_paths = [
        '/login',
        '/signin',
        '/ingresar',
        '/auth',
        '/user/login',
        '/users/login',
        '/account/login',
        '/accounts/login',
        '/admin/login',
        '/access/login',
        '/session/login',
        '/login.php',
        '/login.html',
        '/auth/login',
        '/authenticate',
        '/member/login',
        'es-AR/login'
    ]
    
    if not targets.startswith(('http://', 'https://')):
        targets = 'http://' + targets  # O 'https://' si prefieres HTTPS por defecto

    for path in common_login_paths:
        url = targets.rstrip('/') + path
        try:
            response = requests.get(url)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Buscar un formulario de login
                forms = soup.find_all('form')
                for form in forms:
                    if form.find('input', {'type': 'password'}) and (form.find('input', {'type': 'text'}) or form.find('input', {'type': 'email'})):
                        print(f"Login page found at: {url}")
                        return url
        except requests.RequestException as e:
            print(f"Error al acceder a {url}: {e}")

    print("No login page found.")
    return None

if __name__ == "__main__":
    # Ignorar advertencias sobre SSL
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    targets = input('Escriba el dominio o ip a escanear: ')
    login_url = find_login_url(targets)
    if login_url:
        # inyección SQL en login_url
        pass

