import subprocess

# Solicitar la URL o IP al usuario
url = input("Inserte la URL o IP que quiere escanear: ")

# Comando sqlmap con opciones detalladas para un análisis exhaustivo
command = [
    "sqlmap", "-u", url, "--batch", "--random-agent",
    "--level=5", "--risk=3", "--banner", "--current-user",
    "--current-db", "--is-dba", "--dbs", "--tables",
    "--dump-all"
]

# Ejecutar el comando y capturar la salida en tiempo real
process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Leer la salida línea por línea
for line in process.stdout:
    print(line, end='')  # Imprimir la línea tal cual aparece

# Leer y mostrar cualquier error que ocurra
stderr_output = process.stderr.read()
if stderr_output:
    print("Error:", stderr_output)

# Esperar a que el proceso termine
process.stdout.close()
process.stderr.close()
process.wait()

