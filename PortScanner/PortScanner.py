import socket       #permite establecer la conexion por internet
from IPy import IP

def scan(target):
    converted_ip = check_ip(target)
    print('\n' + '[-_0 Scanning target] ' + str(target))
    for port in range(1,100):
        scan_port(converted_ip, port)

def check_ip(ip):
    try:
        IP(ip)
        return(ip)
    except ValueError:
        return socket.gethostbyname(ip)
    
    
def get_banner(s):
    return s.recv(1024)

def scan_port(ipaddress, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)   #cambiarlo a mi gusto o incluso sacarlo
        sock.connect((ipaddress, port))
        try:
            banner = get_banner(sock)
            print('[+] Puerto abierto '+ str(port) + ' : ' + str(banner.decode().strip('\n')))
        except:
            print('[+] Puerto abierto '+ str(port))
    except:
        pass
        # print('[-] El puerto '+ str(port) + ' esta cerrado')
     
    
targets =  input('Escriba el dominio o ips a escanear (separados por coma): ')
if ',' in targets:
    for ip_add in targets.split(','):
        scan(ip_add.strip(' '))
        
else:
    scan(targets)
 
