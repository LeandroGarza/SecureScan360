import socket       #permite establecer la conexion por internet
from IPy import IP

def scan_port(ipaddress, port):
    try:
     sock = socket.socket()
     sock.settimeout(0.5)   #cambiarlo a mi gusto
     sock.connect((ipaddress, port))
     print('[+] El puerto '+ str(port) + ' esta abierto')
    
    except:
     print('[-] El puerto '+ str(port) + ' esta cerrado')
     
    
ipaddress =  input('[+] Escriba la ip a escanear: ')
 
for port in range(1,10):
    scan_port(ipaddress, port)