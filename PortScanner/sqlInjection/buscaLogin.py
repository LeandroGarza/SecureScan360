import requests
from bs4 import BeautifulSoup

def find_login_url(targets):
    common_login_paths = ['/login', '/signin', '/auth', '/user/login']
    
    for path in common_login_paths:
        url = targets + path
        response = requests.get(url)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar un formulario de login
            forms = soup.find_all('form')
            for form in forms:
                if form.find('input', {'type': 'password'}) and (form.find('input', {'type': 'text'}) or form.find('input', {'type': 'email'})):
                    print(f"Login page found at: {url}")
                    return url
    
    print("No login page found.")
    return None

if __name__ == "__main__":
    targets = input('Escriba el dominio o ip a escanear: ')
    login_url = find_login_url(targets)
    if login_url:
        # inyección SQL en login_url
        pass
