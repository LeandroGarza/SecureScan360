import socket
import subprocess

def get_ip_address(domain):
  
    output = subprocess.run(['dig', '+short', domain], capture_output=True, text=True)

    print("Escaneando el dominio:", output.stdout)

    # Extraer la dirección IP de la salida de dig
    ipaddress = output.stdout.strip().splitlines()[0]
    print("La IP del dominio proporcionado es: ",ipaddress)

    # Si se obtiene una dirección IP válida, retornarla
    if ipaddress:
        
        return ipaddress
    
    # Si no se pudo obtener la dirección IP, retornar None
    return None

# Entrada del usuario para el dominio a escanear
domain = input('[+] Escriba el dominio a escanear: ')

# Obtener la dirección IP del dominio
ipaddress = get_ip_address(domain)

# Si se encontró la dirección IP, continuar con el escaneo del puerto 80
if ipaddress:
    port = 80
    try:
        sock = socket.socket()
        sock.connect((ipaddress, port))
        print('[+] El puerto', port, 'está abierto en la dirección IP', ipaddress)
    except Exception as e:
        print('[-] El puerto', port, 'está cerrado en la dirección IP', domain)
        print('    Error:', e)
else:
    print('[-] No se pudo obtener la dirección IP para el dominio proporcionado.')



