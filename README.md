# SecureScan360

Instrucciones para correr el Front end. 
Una vez ingresado en la carpeta FrontEnd, correr el comando python3 app.py

Instrucciones para correr el Back end. 
Una vez ingresado en la carpeta BackEnd, correr el comando python3 nombredetool.py

## fussion 
funciona el escaneo de puertos con vulnerabilidad y luego fuerza bruta pero para la contrasenia, faltaria agregar para el usuario.

## carpeta bruteforce
## bruteforce
no funciona la fuerza bruta de contrasenia:
 python3 bruteforce.py 
[+] Enter Page URL: http://192.168.0.105
[+] Enter Username For The Account To Bruteforce: msfadmin
[+] Enter Password File To Use: passwords.txt
[+] Enter String That Occurs When Login Fails: Permission denied, please try again.
Enter Cookie Value(Optional): 
Trying: password
[+] Found Username: ==> msfadmin
[+] Found Password: ==> password

## sshbrute
va uno por uno identificando las credenciales y contrase;as
este es el caso del codigo que al poner el usuario correcto en el txt luego del tercer puesto, tira error.
Ahora anda pero con un sleep de 10 en retrying y de 8 en incorrect credentials

disyuntiva entre tiempo de rta
si tarda poco tiempo, entonces el ssh me va a bloquear por intentar muchas veces en tan poco tiempo. Si tarda mucho tiempo el cliente se puede impacientar.

## tethread
es el que mejor anda. Funciona hasta con diccionario largo



