import subprocess

url = input("Inserte la URL o IP que quiere escanear: ")

command = [
    "sqlmap", "-u", url, "--batch", "--random-agent",
    "--level=5", "--risk=3", "--banner", "--current-user",
    "--current-db", "--is-dba", "--dbs", "--tables",
    "--dump-all"
]

process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

for line in process.stdout:
    print(line, end='')

stderr_output = process.stderr.read()
if stderr_output:
    print("Error:", stderr_output)

process.stdout.close()
process.stderr.close()
process.wait()

