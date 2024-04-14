import PortScanner

# print('[+] Puerto abierto '+ str(port) + ' : ' + str(banner.decode().strip('\n')))
# print('[+] Puerto abierto '+ str(port))

targets_ip =  input('Escriba el dominio o ips a escanear (separados por coma): ')
port_num = input('Ingrese la cantidad de puertos que quiere scanear: ')
# vuln_file = input(['Ingrese direccion a carpeta con sw vulnerables])
"""
if ',' in targets_ip:
            for ip_add in targets_ip.split(','):
                #scan(ip_add.strip(' '),port_num)
                scan(ip_add.strip(' '))
        
        else:
            #scan(targets,port_num)
            scan(targets)
"""
print('\n')
target = PortScanner.PortScan(targets_ip, port_num)
target.scan()

