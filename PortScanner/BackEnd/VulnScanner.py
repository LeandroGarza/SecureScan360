"""
import PortScanner

# print('[+] Puerto abierto '+ str(port) + ' : ' + str(banner.decode().strip('\n')))
# print('[+] Puerto abierto '+ str(port))

targets_ip =  input('Escriba el dominio o ips a escanear (separados por coma): ')
port_num = int(input('Ingrese la cantidad de puertos que quiere scanear: '))
# vuln_file = input(['Ingrese direccion a carpeta con sw vulnerables])

if ',' in targets_ip:
            for ip_add in targets_ip.split(','):
                #scan(ip_add.strip(' '),port_num)
                scan(ip_add.strip(' '))
        
        else:
            #scan(targets,port_num)
            scan(targets)

print('\n')
target = PortScanner.PortScan(targets_ip, port_num)
target.scan()

"""
import PortScanner

targets_ip = input('[+] * Enter Target To Scan For Vulnerable Open Ports: ')
port_number = int(input('[+] * Enter Amount Of Ports You Want To Scan(500 - first 500 ports): '))
vul_file = input('[+] * Enter Path To The File With Vulnerable Softwares: ')
print('\n')

target = PortScanner.PortScan(targets_ip, port_number)
target.scan()

with open(vul_file, 'r') as file:
    count = 0

    for banner in target.banners:
        file.seek(0)
        for line in file.readlines():
            if line.strip() in banner:
                print('[!!] VULNERABLE BANNER: "' + banner + '" ON PORT: ' + str(target.open_ports[count]))
        count += 1
        

