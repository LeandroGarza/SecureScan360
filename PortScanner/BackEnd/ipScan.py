import PortScanner

ip = '190.7.56.94'
PortScanner.scan(ip)

"""
targets =  input('Escriba el dominio o ips a escanear (separados por coma): ')
if ',' in targets:
    for ip_add in targets.split(','):
       scan(ip_add.strip(' '))
        
else:
    scan(targets)
"""