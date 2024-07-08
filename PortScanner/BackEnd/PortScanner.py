# version con clases
"""
import socket       #permite establecer la conexion por internet
from IPy import IP


class PortScan():
    banners = []
    def __init__(self, target, port_num):
        self.target = target
        self.port_num = port_num
        
    # def scan(target, port_num):       en caso que le demos los puertos que quiere escanear
    def scan(self):
            
        #podriamos escanear mas puertos
        #for port in range(1,port_num):   en caso q le demos los puertos que quiere escanear
        for port in range(1,100):   
          self.scan_port(port)

    def check_ip(self):
        try:
            IP(self.target)
            return(self.target)
        except ValueError:
            return socket.gethostbyname(self.target)

    def scan_port(self, port):
        try:
            converted_ip = self.check_ip()
            sock = socket.socket()
            sock.settimeout(1)   #cambiarlo a mi gusto o incluso sacarlo
            sock.connect((converted_ip, port))
            self.open_ports.append(port)
            try:
                banner = sock.recv(1024).decode().strip('\n').strip('\r')
                self.banners.append(banner)
            except:
                self.banners.append(' ')
            sock.close()
        except:
            pass
            # print('[-] El puerto '+ str(port) + ' esta cerrado')
     

    if __name__ == "__main__":      #por si lo ejecutamos de otro archivo
        targets =  input('Escriba el dominio o ips a escanear (separados por coma): ')
        # port_num = input('Ingrese la cantidad de puertos que quiere scanear: ')
        if ',' in targets:
            for ip_add in targets.split(','):
                #scan(ip_add.strip(' '),port_num)
                scan(ip_add.strip(' '))
        
        else:
            #scan(targets,port_num)
            scan(targets)


# version que indica que servicio corre en cada puerto
import socket       #permite establecer la conexion por internet
from IPy import IP

def scan(target):
    converted_ip = check_ip(target)
    print('\n' + '[-_0 Scanning target] ' + str(target))
    for port in range(19,500):
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
"""

import nmap

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-p 20,21,22,25,53,80,110,123,143,179,443,465,500,587,993,995,2222,3389,41648 -sV -sC')  # Escaneo de todos los puertos con detección de versiones
    
    with open('vulbanners.txt', 'r') as file:
        #vul_banners = file.read().splitlines()
        vul_banners = [line.strip() for line in file.readlines()]
    
    for host in nm.all_hosts():
        print('\n' + 'Ip obtenida: ' + str(host))
        for proto in nm[host].all_protocols():
            print('Protocolo : %s' % proto)
            ports = nm[host][proto].keys()
            for port in ports:
                product_version = nm[host][proto][port]['product'] + ' ' + nm[host][proto][port]['version']
                print('[+] Puerto abierto ' + str(port) + ' : ' + product_version)
                if product_version in vul_banners:
                    print('[!!] VULNERABLE BANNER: "' + product_version + '" ON PORT: ' + str(port))
                    
targets = input('Escriba el dominio o ip a escanear: ')
input('Escaneo iniciado, esto puede tardar unos minutos..')
if ',' in targets:
    for ip_add in targets.split(','):
        scan(ip_add.strip(' '))
else:
    scan(targets)